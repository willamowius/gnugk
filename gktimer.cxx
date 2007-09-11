/*
 * gktimer.cxx
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
 * Revision 1.4  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.1.1.1  2005/11/21 20:19:58  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.3  2005/04/24 16:39:44  zvision
 * MSVC6.0 compatibility fixed
 *
 * Revision 1.2  2004/05/12 11:47:06  zvision
 * Generic support for time-based events
 *
 * Revision 1.1.2.1  2004/05/10 16:43:26  zvision
 * Generic support for time-based events
 *
 */
#if defined(_WIN32) && (_MSC_VER <= 1200)
#pragma warning(disable:4284)
#endif

#include <ptlib.h>
#include "stl_supp.h"
#include "gktimer.h"

using std::find;

/// A timer that calls a simple void function on its expiration
class GkVoidFuncTimer : public GkTimer
{
public:
	GkVoidFuncTimer(
		const PTime& expirationTime,
		void (*timerFunc)()
		) : GkTimer(expirationTime), m_timerFunc(timerFunc) {}

	GkVoidFuncTimer(
		const PTime& expirationTime,
		long interval,
		void (*timerFunc)()
		) : GkTimer(expirationTime, interval), m_timerFunc(timerFunc) {}

protected:
	virtual void OnTimerExpired() { if (m_timerFunc) (*m_timerFunc)(); }

private:
	GkVoidFuncTimer();

private:
	void (*m_timerFunc)(); /// a simple timer function
};

/// A timer that calls a simple one arg function on its expiration
class GkOneArgFuncTimer : public GkTimer
{
public:
	GkOneArgFuncTimer(
		const PTime& expirationTime,
		void (*timerFunc)(GkTimer*)
		) : GkTimer(expirationTime), m_timerFunc(timerFunc) {}

	GkOneArgFuncTimer(
		const PTime& expirationTime,
		long interval,
		void (*timerFunc)(GkTimer*)
		) : GkTimer(expirationTime, interval), m_timerFunc(timerFunc) {}

protected:
	virtual void OnTimerExpired() { if (m_timerFunc) (*m_timerFunc)(this); }

private:
	GkOneArgFuncTimer();

private:
	void (*m_timerFunc)(GkTimer*); /// a simple timer function
};

const GkTimerManager::GkTimerHandle GkTimerManager::INVALID_HANDLE = NULL;

GkTimerManager::GkTimerManager()
{
}

GkTimerManager::GkTimerHandle GkTimerManager::RegisterTimer(
	void (*timerFunc)(), /// timer function
	const PTime& tm /// timer expiration time
	)
{
	GkTimer* const t = new GkVoidFuncTimer(tm, timerFunc);
	PWaitAndSignal lock(m_timersMutex);
	m_timers.push_back(t);
	return t;
}

GkTimerManager::GkTimerHandle GkTimerManager::RegisterTimer(
	void (*timerFunc)(), /// timer function
	const PTime& tm, /// the first expiration time
	long interval /// timer interval (seconds)
	)
{
	GkTimer* const t = new GkVoidFuncTimer(tm, interval, timerFunc);
	PWaitAndSignal lock(m_timersMutex);
	m_timers.push_back(t);
	return t;
}

GkTimerManager::GkTimerHandle GkTimerManager::RegisterTimer(
	void (*timerFunc)(GkTimer*), /// timer function
	const PTime& tm /// timer expiration time
	)
{
	GkTimer* const t = new GkOneArgFuncTimer(tm, timerFunc);
	PWaitAndSignal lock(m_timersMutex);
	m_timers.push_back(t);
	return t;
}

GkTimerManager::GkTimerHandle GkTimerManager::RegisterTimer(
	void (*timerFunc)(GkTimer*), /// timer function
	const PTime& tm, /// the first timer expiration time
	long interval /// timer interval (seconds)
	)
{
	GkTimer* const t = new GkOneArgFuncTimer(tm, interval, timerFunc);
	PWaitAndSignal lock(m_timersMutex);
	m_timers.push_back(t);
	return t;
}

bool GkTimerManager::UnregisterTimer(
	GkTimerManager::GkTimerHandle timer
	)
{
	PWaitAndSignal lock(m_timersMutex);
	std::list<GkTimerHandle>::iterator i 
		= find(m_timers.begin(), m_timers.end(), timer);
	if (i != m_timers.end()) {
		m_timers.erase(i);
		delete timer;
		return true;
	} else
		return false;
}
	
void GkTimerManager::CheckTimers()
{
	PWaitAndSignal lock(m_timersMutex);
	std::list<GkTimerHandle>::iterator i = m_timers.begin();
	while (i != m_timers.end()) {
		GkTimer* timer = *i++;
		if (timer->IsExpired()) {
			timer->SetFired(true);
			timer->OnTimerExpired();
			if (timer->IsPeriodic())
				timer->SetExpirationTime(timer->GetExpirationTime() 
					+ PTimeInterval(timer->GetInterval() * 1000)
					);
		}
	}
}

GkTimerManager::~GkTimerManager()
{
	PWaitAndSignal lock(m_timersMutex);
	DeleteObjectsInContainer(m_timers);
	m_timers.clear();
}

