//////////////////////////////////////////////////////////////////
//
// SignalConnection.h
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
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

#include "SignalChannel.h"

#include "GkQ931.h"
#include "h225.h"

class SignalChannel;

class SignalConnection:public PThread {

	PCLASSINFO ( SignalConnection, PThread )

	public:
		SignalConnection ( PINDEX stackSize, PIPSocket::Address _GKHome, PTCPSocket * remote, PTCPSocket * local );
		SignalConnection ( PINDEX stackSize, PIPSocket::Address _GKHome, PTCPSocket * caller, SignalChannel * sigChannel );
		virtual ~SignalConnection();
 
		void Main();
		BOOL OnReceivedData ();
		void OnSetup( H225_H323_UU_PDU_h323_message_body & body );
		void OnCallProceeding( H225_H323_UU_PDU_h323_message_body & body );
		void OnConnect( H225_H323_UU_PDU_h323_message_body & body );
		void OnAlerting( H225_H323_UU_PDU_h323_message_body & body );
		void OnInformation( H225_H323_UU_PDU_h323_message_body & body );
		void OnReleaseComplete( H225_H323_UU_PDU_h323_message_body & body );
		void OnFacility( H225_H323_UU_PDU_h323_message_body & body );
		void OnProgress( H225_H323_UU_PDU_h323_message_body & body );
		void OnEmpty( H225_H323_UU_PDU_h323_message_body & body );
		BOOL Send(PTCPSocket *socket);
		void CloseSignalConnection(void);  // cause thread to terminate
		BOOL IsSignalConnectionOpen(void) { return m_connection->IsOpen(); };  // FALSE when thread is just about to terminate


	protected:
		PIPSocket::Address GKHome;
		PTCPSocket		* m_connection;
		PTCPSocket		* m_remote;
		SignalChannel	* m_sigChannel;
		H225_CallReferenceValue m_crv;
		H225_CallIdentifier		callid;

		GkQ931 m_q931;

	private:
		SignalConnection * remoteConnection;
};

#endif

