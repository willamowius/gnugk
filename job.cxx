//////////////////////////////////////////////////////////////////
//
// job.cxx
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


#if (_MSC_VER >= 1200)
#pragma warning( disable : 4355 ) // warning about using 'this' in initializer
#endif

#include "job.h"
#include "rwlock.h"
#include "stl_supp.h"
#include "singleton.h"


class Worker : public PThread {
public:
	PCLASSINFO ( Worker, PThread )

	Worker(int = 10*60);
	~Worker();

	bool Exec(Job *);
	void Destroy();

private:
	// override from class PThread
	virtual void Main();

	PTimeInterval m_timeout;
	PSyncPoint m_sync;
	bool m_closed;
	PMutex m_mutex;
	Job *m_job;
	PThreadIdentifer m_id;
	//volatile Job *m_job;
};

class Agent : public Singleton<Agent> {
public:
	Agent();
	~Agent();

	void Exec(Job *);
	void Remove(Worker *);

private:
	typedef std::list<Worker *>::iterator iterator;
	PReadWriteMutex m_wmutex;
	std::list<Worker *> m_workers;
	iterator m_insp;
};


// class Worker
Worker::Worker(int timeout) : PThread(5000, AutoDeleteThread),
        m_timeout(timeout*1000), m_closed(false), m_job(0)
{
	Resume();
}

Worker::~Worker()
{
	PTRACE(1, "Worker\t" << m_id << " is fired");
	if (m_job) {
		PTRACE(1, "Error: Terminating a busy worker " << m_id << " with job " << m_job->GetName());
		delete m_job;
	}
}

void Worker::Main()
{
#ifdef WIN32
	 m_id = GetThreadId();
#else
     	 m_id = ::getpid();
#endif
	PTRACE(2, "Worker\t" << m_id << " is hired");
	while (!m_closed) {
		if (!m_job && !m_sync.Wait(m_timeout)) {
			Agent::Instance()->Remove(this);
			m_closed = true;
			PTRACE_IF(1, m_job, "Warning: Run job " << m_job->GetName() << " at closing thread " << m_id);
		}
		if (m_job) {
			PTRACE(5, "Job\tRun " << m_job->GetName() << " at thread " << m_id);

			m_job->Run();

			PWaitAndSignal lock(m_mutex);
			delete m_job;
			m_job = 0;
		}
	}
}

bool Worker::Exec(Job *job)
{
	if (m_job == 0) {
		PWaitAndSignal lock(m_mutex);
		// check again after we got the lock
		if (m_job == 0) {
			m_job = job;
			/*
			if (m_sync.WillBlock())
				m_sync.Signal();
			*/
			m_sync.Signal();
			return true;
		}
	}
	return false;
}

void Worker::Destroy()
{
	SetNoAutoDelete();
	m_mutex.Wait();
	if (m_job)
		m_job->Stop();
	m_mutex.Signal();

	m_closed = true;
	m_sync.Signal();
	WaitForTermination();
	cerr << '.';
	delete this;
}


// class Agent
Agent::Agent() : Singleton<Agent>("Agent")
{
	// insert point
	m_insp = m_workers.begin();
//	for (int i = 0; i < 4; ++i)
//		m_workers.push_back(new Worker(86400));
}

Agent::~Agent()
{
	ForEachInContainer(m_workers, mem_vfun(&Worker::Destroy));
}

void Agent::Exec(Job *job)
{
	bool notfound = false;
	if (job) {
		ReadLock lock(m_wmutex);
		notfound = find_if(m_workers.begin(), m_workers.end(), bind2nd(mem_fun(&Worker::Exec), job)) == m_workers.end();
	}
	if (notfound) {
		Worker *aworker = new Worker;
		bool isregular = dynamic_cast<RegularJob *>(job);
		aworker->Exec(job);
		WriteLock lock(m_wmutex);
		iterator ninsp = m_workers.insert(m_insp, aworker);
		// always point to the beginning of thread of RegularJob
		if (isregular)
			m_insp = ninsp;
	}
}

void Agent::Remove(Worker *aworker)
{
	WriteLock lock(m_wmutex);
	m_workers.remove(aworker);
}


// class Job
Job::~Job()
{
	PTRACE(5, "Job\tDelete " << GetName());
}

void Job::Execute()
{
	Agent::Instance()->Exec(this);
}

void Job::StopAll()
{
	delete Agent::Instance();
}


// class Task
Task *Task::DoNext()
{
	Task *next = m_next;
	m_done = true;
	return next;
}


// class Jobs
void Jobs::Run()
{
	while (m_current) {
		m_current->Exec();
		m_current = m_current->DoNext();
	}
}


// class RegularJob
RegularJob::RegularJob() : Jobs(this)
{
	// repeat this job
	SetNext(this);
}

void RegularJob::Run()
{
	if (OnStart())
		Jobs::Run();
	PWaitAndSignal lock(m_smutex);
	OnStop();
}

void RegularJob::Stop()
{
	SetNext(0);
	Signal();
}

void RegularJob::Wait()
{
	m_sync.Wait();
}

void RegularJob::Signal()
{
	if (m_sync.WillBlock())
		m_sync.Signal();
}
