//////////////////////////////////////////////////////////////////
//
// SignalConnection.h
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Sergio Artero
// initial version: 12/9/1999
//
//////////////////////////////////////////////////////////////////

#ifndef _signalconnection_h__
#define _signalconnection_h__

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <ptclib/asner.h>
#include <h225.h>
#include <q931.h>

#include "RasTbl.h"

class SignalChannel;

class H245Thread {
// TODO
};

class SignalConnection : public PThread {

	PCLASSINFO ( SignalConnection, PThread )

	public:
		SignalConnection ( PINDEX stackSize, PIPSocket::Address _GKHome, PTCPSocket * remote, PTCPSocket * local, const Q931 & caller_m_q931 );
		SignalConnection ( PINDEX stackSize, PIPSocket::Address _GKHome, PTCPSocket * caller, SignalChannel * sigChannel );
		virtual ~SignalConnection();
 
		void Main();
		BOOL OnReceivedData ();
		void OnSetup( H225_Setup_UUIE & Setup );
		void OnCallProceeding( H225_CallProceeding_UUIE & CallProceeding );
		void OnConnect( H225_Connect_UUIE & Connect );
		void OnAlerting( H225_Alerting_UUIE & Alerting );
		void OnInformation( H225_Information_UUIE & Information );
		void OnReleaseComplete( H225_ReleaseComplete_UUIE & ReleaseComplete );
		void OnFacility( H225_Facility_UUIE & Facility );
		void OnProgress( H225_Progress_UUIE & Progress );
		void OnEmpty( H225_H323_UU_PDU_h323_message_body & Empty );
		BOOL Send(PTCPSocket *socket, const Q931 &toSend);
		void CloseSignalConnection(void);  // cause thread to terminate
		BOOL IsSignalConnectionOpen(void) { return m_connection->IsOpen(); };  // FALSE when thread is just about to terminate
		BOOL ShouldBeTerminated(void) { return killMe; };
		void SendReleaseComplete();

	protected:
		PIPSocket::Address GKHome;
		PTCPSocket		* m_connection;
		PTCPSocket		* m_remote;
		SignalChannel	* m_sigChannel;
		H225_CallReferenceValue m_crv;
		H225_CallIdentifier	m_callid;

		Q931 m_q931;
		BOOL bH245Routing;
		H245Thread *m_h245_thread;

	private:
		SignalConnection * remoteConnection;
		int pendingCount;
		PString connectionName;
		Q931 statusEnquiry;
		BOOL killMe;
		callptr pCallRec;
		PMutex m_CloseMutex;
};

#endif

