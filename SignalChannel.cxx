//////////////////////////////////////////////////////////////////
//
// SignalChannel.cxx
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

#include "SignalChannel.h"
#include "q931.h"
#include "ANSI.h"
#include "SignalConnection.h"
#include "Toolkit.h"
#include "gk_const.h"




SignalChannel::SignalChannel ( PINDEX stackSize, PIPSocket::Address _GKHome, WORD port ): 
			PThread( stackSize, NoAutoDeleteThread ),
			m_listener(port)
{
	PTRACE(6, ANSI::CYA << "SignalChannel::SignalChannel" << ANSI::OFF);
	GKHome = _GKHome;
	Resume();
};

BOOL SignalChannel::Open(void)
{
	PTRACE(6, ANSI::CYA << "SignalChannel::Open" << ANSI::OFF);
	// Start socket to listen messages received from signal port.
	return m_listener.Listen(GKHome,
							 GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH),
							 m_listener.GetPort(),
							 PSocket::CanReuseAddress);
};

SignalChannel::~SignalChannel()
{
	PTRACE(6, ANSI::CYA << "SignalChannel::~SignalChannel" << ANSI::OFF);
}


/* Go through the connection list, checking for closed connections.
 * If found, Wait for the thread to termenate then delete the object.
 * Normally the connection thread should self terminate if the connection is lost
 */
void SignalChannel::CleanupConnections(void)
{
	PTRACE(6, ANSI::CYA << "SignalChannel::CleanupConnections" << ANSI::OFF);

	SignalConnection * connection = NULL;
	int num = connectionList.GetSize();

	for(int i=num; --i >= 0; )
	{
		connection = (SignalConnection*) connectionList.GetAt(i);
		if (connection != NULL)
		{
			if (!connection->IsSignalConnectionOpen())
			{
				// Make sure the thread has terminated
				connection->WaitForTermination();
				connectionList.Remove(connection);
				// if list is set to auto destroy object, then remove the following
				// delete connection;
			}
		}
		else
		{
			PTRACE(1,"SignalChannel\tWarning: connectionList() returned NULL");
			break;
		}
	}
}


/* Go through all the connections and signal them to close */
void SignalChannel::CloseConnections(void)
{
	PTRACE(6, ANSI::CYA << "SignalChannel::CloseConnections" << ANSI::OFF);

	SignalConnection * connection = NULL;
	int num = connectionList.GetSize();

	for(int i=num; --i >= 0; )
	{
		connection = (SignalConnection*) connectionList.GetAt(i);
		if (connection != NULL)
		{
			// If thread is still running
			if (connection->IsSignalConnectionOpen())
				connection->CloseSignalConnection();  // signal it to stop
		}
		else
		{
			PTRACE(1,"SignalChannel\tconnectionList() returned NULL");
		}
	}
}


void SignalChannel::Main(void)
{
	PTRACE(6, ANSI::CYA << "SignalChannel::Main" << ANSI::OFF);
	
	PTCPSocket *signallingChannel = new PTCPSocket;

	m_listener.Listen(GKHome,
					  GkConfig()->GetInteger("ListenQueueLength", GK_DEF_LISTEN_QUEUE_LENGTH),
					  m_listener.GetPort(),
					  PSocket::CanReuseAddress);

	// make call to accept block for this amount of time.
	m_listener.SetReadTimeout(GkConfig()->GetInteger("SignalReadTimeout", 1000));  
	while ( m_listener.IsOpen() )
	{
		CleanupConnections(); // free memory of any closed connections

		// only blocks for 1 second, then to check for closed connections.
		// This function is supposed to be blocking until a connect message is received
		// from remote endpoint. This usually happens when ARQ/ACF exchange is completed.
		if ( ! signallingChannel->Accept( m_listener ) ) 
		{
			PChannel::Errors err = signallingChannel->GetErrorCode();
			if ( err == PTCPSocket::Interrupted )
				continue;
			if (err != PTCPSocket::Timeout)
			{   // Error
				PTRACE(4, "GK\tREMOTE CONNECTION NOT ACCEPTED: " << (int) err);
				break;   /* break out of while loop */
			}
			// Timeout on accept, we use this to look for any closed connections
			// plus if a connection has come in, we do that to.
			// BELOW
		}
		else  // incoming connection
		{
			PTRACE(4, "GK\tCONNECTED TO REMOTE ENDPOINT.");
			
			// A new SignalConnection object is created to handle incoming messages: processing and routing to
			// remote endpoint.
			SignalConnection *connection = new SignalConnection( 1000, GKHome, signallingChannel, this );
			connectionList.Append(connection); 
			
			// To establish a connection a new socket is needed. This socket is associated to
			// listening socket and will handle future connection.
			signallingChannel = new PTCPSocket;  
		}
	}
	
	delete signallingChannel;  // delete unused socket
	
	CloseConnections();
	CleanupConnections(); // free memory of closed connections
};


void SignalChannel::Close(void)
{
	PTRACE(6, ANSI::CYA << "SignalChannel::Close" << ANSI::OFF);

	PTRACE(2, "GK\tClosing SignalChannel");
	m_listener.Close();
};

