//////////////////////////////////////////////////////////////////
//
// job.h
//
// Abstraction of threads' jobs
//
// Copyright (c) Citron Network Inc. 2002-2003
// Copyright (c) 2006-2015, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef JOB_H
#define JOB_H "@(#) $Id$"

#include "name.h"

// timeout (seconds) for an idle Worker to be deleted
#define DEFAULT_WORKER_IDLE_TIMEOUT (60*60)		// 60 minutes
extern long g_workerIdleTimeout;

/** The base abstract class that represents job objects.
    This class implements the way to execute the job.
    Derived classes implement actual jobs (override Run()).
	Jobs are executed and managed by the internal Job management system
	consisting of the singleton Agent object and Worker threads
	that accept and execute new Jobs.

	Specialized Job examples are:
    Jobs - executes series of Tasks
    RegularJob - executes a Task again and again until stopped
    SimpleClassJob - calls a member function of some class that takes no arguments
    SimpleClassJobA - calls a member function of some class that takes one
	                  argument of reference type
*/
class Job : public NamedObject
{
public:
	Job() { }
	virtual ~Job();

	/// Perform the actual job, return when it is done
	virtual void Run() = 0;

	/// Stop a running job
	virtual void Stop();

	/** Execute the job in a first idle Worker thread.
		The function returns immediately and this object
		is delete automatically, when the job is finished.
	*/
	void Execute();

	/// Stop all jobs being currently executed by Worker threads
	static void StopAll();

private:
	Job(const Job &);
	Job& operator=(const Job &);
};

/** Similar to the Job, but is even more abstract. It does not contain
	any Task management routines. Main purpose of this class it to provide
	a way to represent a series of Tasks that are to be executed one after another.
*/
class Task
{
public:
	Task() : m_next(NULL), m_done(false) { }
	virtual ~Task();

	/// Perform the actual task and return when it is finished
	virtual void Exec() = 0;

	/** @return
	    true if the task is done and a next task is being processed.
	*/
	bool IsDone() const { return m_done; }

	/// Setup a task to be executed when this one is done
	void SetNext(
		/// next task to be executed
		Task* next
		)
	{
		if (m_next != NULL && m_next != this)
			m_next->SetNext(next);
		else
			m_next = next;
	}

	/** @return
	    true if this is not the last task.
	*/
	bool HasNext() const { return m_next != NULL; }

	/** Get a next task and mark this one as done.
	    @return
	    The task that is next or NULL if this is the last task.
	*/
	Task* DoNext()
	{
		Task* next = m_next;
		if (next != this) // do not set m_done flag for circular task
			m_done = true;
		return next;
	}

private:
	/// next task to be executed when this one is done
	Task* m_next;
	/// true if the task is finished
	bool m_done;
};


/// Execute a task or a series of tasks
class Jobs : public Job
{
public:
	Jobs(
		/// task to be executed
		Task* task
		) : m_current(task) {}

	/// process the associated task (override from Job)
	virtual void Run();

private:
	Jobs();
	Jobs(const Jobs &);
	Jobs& operator=(const Jobs &);

private:
	/// task (or a serie of tasks) to be executed
	Task* m_current;
};

/** Regular job - executes the same task until it is stopped
	(by calling Stop()). The actual work is to be done in the virtual
	Exec() method in derived classes. RegularJob is an abstract class.
*/
class RegularJob : public Job
{
public:
	RegularJob();
	virtual ~RegularJob() { }

	/** @return
		true if the job has not been yet stopped
	*/
	bool IsRunning() const { return !m_stop; }

	/// override from Job
	virtual void Run();

	/// repeated activity to be executed by this RegularJob
	virtual void Exec() = 0;

	/** Stop this job. NOTE: Acquire m_deletionPreventer mutex first
	    to make sure this object is not deleted before the method that
		called Stop returns (if Stop is called from a derived class).
	*/
	virtual void Stop();

protected:
	// new virtual function

	/// Callback function that is called before the job is started.
	virtual void OnStart();

	/** Callback function that is called when the job is stopped.
		NOTE: This function is called with m_deletionPreventer mutex acquired.
	*/
	virtual void OnStop();

	/// Wait for a signal (Signal())
	void Wait() { m_sync.Wait(); }

	/** Wait for a signal (Signal()).

	    @return
	    true if the sync point has been signaled.
	*/
	bool Wait(
		/// time to wait for the sync point to be signaled
		const PTimeInterval& timeout
		)
	{
		return m_sync.Wait(timeout);
	}

	/// Send a signal to the waiting task
	void Signal() { m_sync.Signal(); }

private:
	RegularJob(const RegularJob &);
	RegularJob& operator=(const RegularJob &);

protected:
	/// can be used when calling Stop to prevent the job to be deleted
	/// (and invalid object being referenced) before the function
	/// that called Stop returns
	PMutex m_deletionPreventer;

private:
	/// used by Wait and Signal member functions
	PSyncPoint m_sync;
	/// true if the job should be stopped
	volatile bool m_stop;
};


// helper to start a thread without parameter
template<class T>
class SimpleClassJob : public Job {
public:
	SimpleClassJob(T *_t, void (T::*_j)()) : t(_t), j(_j) { }
	virtual void Run() { (t->*j)(); }

private:
	T *t;
	void (T::*j)();
};

// helper to start a thread with one parameter
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

// start a thread without parameter
template<class T>
void CreateJob(T *t, void (T::*j)(), const char *jobname)
{
	Job *newjob = new SimpleClassJob<T>(t, j);
	newjob->SetName(jobname);
	newjob->Execute();
}

// start a thread with one parameter
template<class T, class A>
void CreateJob(T *t, void (T::*j)(A), A a, const char *jobname)
{
	Job *newjob = new SimpleClassJobA<T, A>(t, j, a);
	newjob->SetName(jobname);
	newjob->Execute();
}

#endif // JOB_H
