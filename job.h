//////////////////////////////////////////////////////////////////
//
// job.h
//
// Abstraction of threads' jobs
//
// Copyright (c) Citron Network Inc. 2002-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chin-Wei Huang <cwhuang@linux.org.tw>
// initial version: 04/21/2003
//
//////////////////////////////////////////////////////////////////

#ifndef JOB_H
#define JOB_H "@(#) $Id$"

#ifndef _PTLIB_H
#include <ptlib.h>
#endif
#ifndef NAME_H
#include "name.h"
#endif

// abstraction of a gatekeeper job
class Job : public NamedObject {
public:
	virtual ~Job();

	// do the job
	// return true if job is done
	virtual void Run() = 0;

	// stop the job
	virtual void Stop() { /* nothing */ }

	// execute the job in a free thread and delete it after done
	void Execute();

	// stop all jobs when gatekeeper exits
	static void StopAll();
};

// component of a series of jobs
class Task {
public:
	Task() : m_next(0), m_done(false) {}
	virtual ~Task() {}

	virtual void Exec() = 0;

	bool IsDone() const { return m_done; }
	void SetNext(Task *n) { m_next = n; }
	Task *GetNext() const { return m_next; }
	Task *DoNext();

private:
	Task *m_next;
	bool m_done;
};

// a series of tasks
class Jobs : public Job {
public:
	Jobs(Task *task) : m_current(task) {}

	// override from class Job
	virtual void Run();

private:
	Task *m_current;
};

// a regular job
class RegularJob : public Jobs, protected Task {
public:
	RegularJob();

	bool IsRunning() const { return GetNext() != 0; }

	// override from class Jobs
	virtual void Run();
	virtual void Stop();

protected:
	// new virtual function

	// called when the job is started
	virtual bool OnStart() { return true; }

	// called by the system when the job is stopped
	virtual void OnStop() {}

	// wait for an event before doing the task
	// return true if an expected event is received
	// default behavior: wait for a signal to the specified SyncPoint
	virtual void Wait();

	// go on doing the job
	virtual void Signal();

	PSyncPoint m_sync;
	PMutex m_smutex;
};

template<class F, class T>
class SimpleJob : public Job {
public:
	SimpleJob(const F & _f, T *_t) : f(_f), t(_t) {}
	virtual void Run() { f(t); }

private:
	const F f;
	T *t;
};

template<class F, class T, class A>
class SimpleJobA : public Job {
public:
	SimpleJobA(const F & _f, T *_t, const A & _a) : f(_f), t(_t), a(_a) {}
	virtual void Run() { f(t, a); }

private:
	const F f;
	T *t;
	A a;
};

template<class T>
class SimpleClassJob : public Job {
public:
	SimpleClassJob(T *_t, void (T::*_j)()) : t(_t), j(_j) {}
	virtual void Run() { (t->*j)(); }

private:
	T *t;
	void (T::*j)();
};

template<class T, class A>
class SimpleClassJobA : public Job {
public:
	typedef void (T::*CJob)(A);
	SimpleClassJobA(T *_t, CJob _j, A _a) : t(_t), j(_j), a(_a) {}
	virtual void Run() { (t->*j)(a); }

private:
	T *t;
	CJob j;
	A a;
};

template<class T>
void CreateJob(T *t, void (T::*j)(), const PString & n)
{
	Job *newjob = new SimpleClassJob<T>(t, j);
	newjob->SetName(n);
	newjob->Execute();
}

template<class T, class A>
void CreateJob(T *t, void (T::*j)(A), A a, const PString & n)
{
	Job *newjob = new SimpleClassJobA<T, A>(t, j, a);
	newjob->SetName(n);
	newjob->Execute();
}

#endif // JOB_H
