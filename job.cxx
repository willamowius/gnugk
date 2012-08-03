//////////////////////////////////////////////////////////////////
//
// job.cxx
//
// Abstraction of threads' jobs
//
// Copyright (c) Citron Network Inc. 2002-2003
// Copyright (c) 2006-2010, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include <list>
#include <ptlib.h>
#include "stl_supp.h"
#include "rwlock.h"
#include "singleton.h"
#include "config.h"
#include "job.h"

// timeout (seconds) for an idle Worker to be deleted
#define DEFAULT_WORKER_IDLE_TIMEOUT (10*60)

/** This class represents a thread that performs jobs. It has two states:
    idle and busy. When it accepts a new Job, it becomes busy. When the job
    is finished it becomes idle. Each idle Worker is stopped (deleted) after
    the specified timeout, so Workers that are not needed anymore do not use
    system resources. This makes passible to create dynamic sets of Workers.
*/
class Agent;
class Worker : public PThread 
{
public:
	PCLASSINFO(Worker, PThread)

	/// create a new Worker thread and start it immediately
	Worker(
		/// pointer to the Agent instance that is controlling this worker
		Agent* agent,
		/// timeout (seconds) for this Worker to be deleted, if idle
		long idleTimeout = DEFAULT_WORKER_IDLE_TIMEOUT
		);
	
	virtual ~Worker();

	/** Tell this Worker to execute a new Job. The function returns
		immediately and the job is executed under control of the Worker thread.
		After the job is finished, its object is deleted.
		
		@return
		true if this Worker is idle and has taken the Job, false otherwise 
		(on failuer the job object is not deleted).
	*/
	bool Exec(
		/// Job to be executed
		Job* job
		);
		
	/** Stop the Worker thread and any jobs being executed, 
	    wait for Worker thread termination and delete this object.
	*/
	void Destroy();

	// override from class PThread
	virtual void Main();
	
private:
	Worker();
	Worker(const Worker&);
	Worker& operator=(const Worker&);

private:
	/// idle timeout (seconds), after which the Worker is destoyed
	PTimeInterval m_idleTimeout;
	/// signals that either a new Job is present or the Worker is destroyed
	PSyncPoint m_wakeupSync;
	/// true if the Worker is being destroyed
	volatile bool m_closed;
	/// for atomic job insertion and deletion
	PMutex m_jobMutex;
	/// actual Job being executed, NULL if the Worker is idle
	Job* volatile m_job;
	/// Worker thread identifier
	PThreadIdentifier m_id;
	/// Agent singleton pointer to avoid unnecessary Instance() calls
	Agent* m_agent;
};

/** Agent singleton manages a set of Worker threads. It creates
    new Workers if required. Idle Workers are deleted automatically
	after configured idle timeout.
*/
class Agent : public Singleton<Agent> 
{
public:
	Agent();
	virtual ~Agent();

	/** Execute the job by the first idle Worker or a new Worker.
		Delete the Job object after it is done.
	*/
	void Exec(
		/// the job to be executed
		Job* job
		);
		
	/** Remove the Worker from busy and idle lists. 
		Called by the Worker when it deletes itself.
	*/
	void Remove(
		/// the worker to be removed from the lists
		Worker* worker
		);

	/** Move the Worker from the busy list to the idle list. 
		Called by the Worker when it finishes each job.
	*/
	void JobDone(
		/// the worker to be marked as idle
		Worker* worker
		);

private:
	Agent(const Agent&);
	Agent& operator=(const Agent&);
			
private:
	/// mutual access to Worker lists
	PMutex m_wlistMutex;
	/// list of idle Worker threads
	std::list<Worker*> m_idleWorkers;
	/// list of Worker threads executing some Jobs
	std::list<Worker*> m_busyWorkers;
	/// flag preventing new workers to be registered during Agent destruction
	volatile bool m_active;
};


Worker::Worker(
	/// pointer to the Agent instance that the worker is run under control of
	Agent* agent,
	/// timeout (seconds) for this Worker to be deleted, if idle
	long idleTimeout
	) 
	: PThread(5000, AutoDeleteThread),
	m_idleTimeout(idleTimeout*1000), m_closed(false), m_job(NULL), m_id(0),
	m_agent(agent)
{
	// resume suspended thread (and run Main)
	Resume();
}

Worker::~Worker()
{
	PWaitAndSignal lock(m_jobMutex);
	if (m_job) {
		PTRACE(1, "JOB\tDestroying Worker " << m_id << " with active Job " << m_job->GetName());
		delete m_job;
		m_job = NULL;
	}
	PTRACE(5, "JOB\tWorker " << m_id << " destroyed");
}

void Worker::Main()
{
	m_id = GetThreadId();
	PTRACE(5, "JOB\tWorker " << m_id << " started");
	
	while (!m_closed) {
		bool timedout = false;
		// wait for a new job or idle timeout expiration
		if (m_job == NULL) {
			timedout = !m_wakeupSync.Wait(m_idleTimeout);
			if (timedout) {
				PTRACE(5, "JOB\tIdle timeout for Worker " << m_id);
			}
		}
		// terminate this worker if closed explicitly or idle timeout expired
		if (m_closed || (timedout && m_job == NULL)) {
			m_closed = true;
			break;
		}
		
		if (m_job) {
			PTRACE(5, "JOB\tStarting Job " << m_job->GetName() 
				<< " at Worker thread " << m_id
				);

			m_job->Run();

			{
				PWaitAndSignal lock(m_jobMutex);
				delete m_job;
				m_job = NULL;
			}
			
			m_agent->JobDone(this);
		}
	}

	PTRACE(5, "JOB\tWorker " << m_id << " closed");
	
	// remove this Worker from the list of workers
	m_agent->Remove(this);
	if (m_job) {
		PTRACE(1, "JOB\tActive Job " << m_job->GetName() 
			<< " left at closing Worker thread " << m_id);
	}
}

bool Worker::Exec(
	/// Job to be executed
	Job* job
	)
{
	// fast check if there is no job being executed
	if (m_job == 0 && !m_closed) {
		PWaitAndSignal lock(m_jobMutex);
		// check again there is no job being executed
		if (m_job == 0 && !m_closed) {
			m_job = job;
			m_wakeupSync.Signal();
			return true;
		}
	}
	return false;
}

void Worker::Destroy()
{
	// do not delete itself when the thread is stopped
	SetNoAutoDelete();
	
	m_jobMutex.Wait();
	if (m_job)
		m_job->Stop();
	m_jobMutex.Signal();

	m_closed = true;
	m_wakeupSync.Signal();
	
	PTRACE(5, "JOB\tWaiting for Worker thread " << m_id << " termination");
	WaitForTermination(5 * 1000);	// max. wait 5 sec.
}


Agent::Agent() : Singleton<Agent>("Agent"), m_active(true)
{
}

Agent::~Agent()
{
	PTRACE(5, "JOB\tDestroying active Workers for the Agent");

	std::list<Worker*> workers;
	int numIdleWorkers = -1;
	int numBusyWorkers = -1;
	
	{
		// move all workers to the local list
		PWaitAndSignal lock(m_wlistMutex);
		m_active = false;
		numIdleWorkers = m_idleWorkers.size();
		numBusyWorkers = m_busyWorkers.size();
		while (!m_busyWorkers.empty()) {
			workers.push_front(m_busyWorkers.front());
			m_busyWorkers.pop_front();
		}
		while (!m_idleWorkers.empty()) {
			workers.push_front(m_idleWorkers.front());
			m_idleWorkers.pop_front();
		}
	}

	PTRACE(5, "JOB\tWorker threads to cleanup: " << (numBusyWorkers+numIdleWorkers) 
		<< " total - " << numBusyWorkers << " busy, " << numIdleWorkers << " idle");

	std::list<Worker*>::iterator iter = workers.begin();
	while (iter != workers.end()) {
		Worker * w = *iter;
		workers.erase(iter++);
		w->Destroy();
#if !defined(_WIN32) || (PTLIB_VER <= 2100)
		delete w;	// don't delete on Windows, issue with PTLib 2.10.1+
#endif
	}
	
	PTRACE(5, "JOB\tAgent and its Workers destroyed");
}

void Agent::Exec(Job * job)
{
	Worker* worker = NULL;
	int numIdleWorkers = -1;
	int numBusyWorkers = -1;
	// pop the first idle worker and move it to the busy list	
	if (job) {
		PWaitAndSignal lock(m_wlistMutex);
		// delete the job if the Agent is being destroyed
		if (!m_active) {
			PTRACE(5, "JOB\tAgent did not accept Job " << job->GetName());
			delete job;
			job = NULL;
			return;
		}
		if (!m_idleWorkers.empty()) {
			worker = m_idleWorkers.front();
			m_idleWorkers.pop_front();
			m_busyWorkers.push_front(worker);
			numIdleWorkers = m_idleWorkers.size();
			numBusyWorkers = m_busyWorkers.size();
		}
	} else
		return;
	
	bool destroyWorker = false;
		
	// if no idle worker has been found, create a new one 
	// and put it on the list of busy workers
	if (worker == NULL) {
		worker = new Worker(this);
		PWaitAndSignal lock(m_wlistMutex);
		if (m_active)
			m_busyWorkers.push_front(worker);
		else
			destroyWorker = true;
		numIdleWorkers = m_idleWorkers.size();
		numBusyWorkers = m_busyWorkers.size();
	}
	
	// execute the job by the worker
	if (!(m_active && worker->Exec(job))) {
		// should not ever happen, but...
		delete job;
		job = NULL;
		PWaitAndSignal lock(m_wlistMutex);
		m_busyWorkers.remove(worker);
		if (m_active)
			m_idleWorkers.push_front(worker);
		else
			destroyWorker = true;
		numIdleWorkers = m_idleWorkers.size();
		numBusyWorkers = m_busyWorkers.size();
	}

	PTRACE_IF(5, m_active, "JOB\tWorker threads: " << (numBusyWorkers+numIdleWorkers) 
		<< " total - " << numBusyWorkers << " busy, " << numIdleWorkers << " idle");

	if (destroyWorker) {
		PTRACE(5, "JOB\tAgent did not accept Job " << job->GetName());
		worker->Destroy();
	}
}

void Agent::Remove(
	Worker* worker
	)
{
	int numIdleWorkers;
	int numBusyWorkers;
	{
		PWaitAndSignal lock(m_wlistMutex);
		// check both lists for the worker
		m_idleWorkers.remove(worker);
		m_busyWorkers.remove(worker);
		numIdleWorkers = m_idleWorkers.size();
		numBusyWorkers = m_busyWorkers.size();
	}
	PTRACE_IF(5, m_active, "JOB\tWorker threads: " << (numBusyWorkers+numIdleWorkers) 
		<< " total - " << numBusyWorkers << " busy, " << numIdleWorkers << " idle");
}

void Agent::JobDone(
	/// the worker to be marked as idle
	Worker* worker
	)
{
	int numIdleWorkers;
	int numBusyWorkers;
	{
		PWaitAndSignal lock(m_wlistMutex);
		m_busyWorkers.remove(worker);
		if (m_active)
			m_idleWorkers.push_front(worker);
		numIdleWorkers = m_idleWorkers.size();
		numBusyWorkers = m_busyWorkers.size();
	}
	PTRACE_IF(5, m_active, "JOB\tWorker threads: " << (numBusyWorkers+numIdleWorkers) 
		<< " total - " << numBusyWorkers << " busy, " << numIdleWorkers << " idle");
}


Task::~Task()
{
}

Job::~Job()
{
	PTRACE(5, "JOB\tJob " << GetName() << " deleted");
}

void Job::Execute()
{
	Agent::Instance()->Exec(this);
}

void Job::Stop()
{
}

void Job::StopAll()
{
	delete Agent::Instance();
}


void Jobs::Run()
{
	while (m_current) {
		m_current->Exec();
		m_current = m_current->DoNext();
	}
}


RegularJob::RegularJob() : m_stop(false)
{
}

void RegularJob::OnStart()
{
}

void RegularJob::OnStop()
{
}

void RegularJob::Run()
{
	OnStart();
	
	while (!m_stop)
		Exec();
		
	// lock to allow a member function that is calling Stop
	// return before OnStop is called and the object is deleted
	PWaitAndSignal lock(m_deletionPreventer);
	OnStop();
}

void RegularJob::Stop()
{
	// signal stop flag and wake up job thread, if it is in the waiting state
	m_stop = true;
	m_sync.Signal();
}
