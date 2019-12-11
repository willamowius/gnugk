/*
 * amqpacct.cxx
 *
 * accounting module for GNU Gatekeeper that sends messages to MQTT and AMQP queues
 *
 * Copyright (c) 2018-2019, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"
#include "gkacct.h"
#include "Toolkit.h"

// superclass for all MQ loggers
class MQAcct : public GkAcctLogger
{
public:
	enum Constants
	{
		/// events recognized by all MQ modules
		MQAcctEvents = AcctStart | AcctStop | AcctUpdate | AcctConnect | AcctAlert | AcctRegister | AcctUnregister | AcctOn | AcctOff | AcctReject
	};

	MQAcct(
		/// name from Gatekeeper::Acct section
		const char* moduleName,
		/// config section name to be used with an instance of this module,
		/// pass NULL to use a default section (named "moduleName")
		const char* cfgSecName = NULL
		);

	/// Destroy the accounting logger
	virtual ~MQAcct();

	/// overridden from GkAcctLogger
	virtual Status Log(AcctEvent evt, const callptr & call);

	/// overridden from GkAcctLogger
	virtual Status Log(AcctEvent evt, const endptr & ep);

protected:
    virtual void Connect() = 0;
    virtual void Disconnect() = 0;
	virtual Status MQLog(const PString & event, const PString & topic) = 0;

protected:
    PString m_host;
    WORD m_port;
    PString m_user;
    PString m_password;
    bool m_useSSL;
    PString m_caCert;

	/// parametrized strings for the events
	PString m_startEvent;
	PString m_stopEvent;
	PString m_updateEvent;
	PString m_connectEvent;
	PString m_alertEvent;
	PString m_registerEvent;
	PString m_unregisterEvent;
	PString m_onEvent;
	PString m_offEvent;
	PString m_rejectEvent;

	PString m_callTopic;
	PString m_regTopic;

	/// timestamp formatting string
	PString m_timestampFormat;
};

MQAcct::MQAcct(const char* moduleName, const char* cfgSecName)
    : GkAcctLogger(moduleName, cfgSecName)
{
	// it is very important to set what type of accounting events
	// are supported for each accounting module, otherwise the Log method
	// will no get called
	SetSupportedEvents(MQAcctEvents);

	PConfig* cfg = GetConfig();
	const PString & cfgSec = GetConfigSectionName();

	m_host = cfg->GetString(cfgSec, "Host", "localhost");
    m_host = Toolkit::Instance()->ReplaceGlobalParams(m_host);
	PString port = cfg->GetString(cfgSec, "Port", "5672");
    port = Toolkit::Instance()->ReplaceGlobalParams(port);
    m_port = (WORD)port.AsUnsigned();
	m_user = cfg->GetString(cfgSec, "User", "guest");
    m_user = Toolkit::Instance()->ReplaceGlobalParams(m_user);
	m_password = cfg->GetString(cfgSec, "Password", "guest");
    m_password = Toolkit::Instance()->ReplaceGlobalParams(m_password);
	PString useSSL = cfg->GetString(cfgSec, "UseSSL", "0");
    useSSL = Toolkit::Instance()->ReplaceGlobalParams(useSSL);
    m_useSSL = Toolkit::AsBool(useSSL);
	m_caCert = cfg->GetString(cfgSec, "CACert", "");
    m_caCert = Toolkit::Instance()->ReplaceGlobalParams(m_caCert);

	m_timestampFormat = cfg->GetString(cfgSec, "TimestampFormat", "");
	m_startEvent = cfg->GetString(cfgSec, "StartEvent", "");
	m_stopEvent = cfg->GetString(cfgSec, "StopEvent", "");
	m_updateEvent = cfg->GetString(cfgSec, "UpdateEvent", "");
	m_connectEvent = cfg->GetString(cfgSec, "ConnectEvent", "");
	m_alertEvent = cfg->GetString(cfgSec, "AlertEvent", "");
	m_registerEvent = cfg->GetString(cfgSec, "RegisterEvent", "");
	m_unregisterEvent = cfg->GetString(cfgSec, "UnregisterEvent", "");
	m_onEvent = cfg->GetString(cfgSec, "OnEvent", "");
	m_offEvent = cfg->GetString(cfgSec, "OffEvent", "");
	m_rejectEvent = cfg->GetString(cfgSec, "RejectEvent", "");

#ifdef P_SSL
    if (m_useSSL) {
        Toolkit::Instance()->InitOpenSSL(); // makes sure  OpenSSL gets initialized exactly once for the whole application
    }
#endif // P_SSL
}

MQAcct::~MQAcct()
{
}

GkAcctLogger::Status MQAcct::Log(GkAcctLogger::AcctEvent evt, const callptr & call)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;

	if (!call && evt != AcctOn && evt != AcctOff) {
		PTRACE(1, "MQAcct\t" << GetName() << " - missing call info for event " << evt);
		return Fail;
	}

	PString event;
	if (evt == AcctStart) {
		event = m_startEvent;
	} else if (evt == AcctConnect) {
		event = m_connectEvent;
	} else if (evt == AcctUpdate) {
		event = m_updateEvent;
	} else if (evt == AcctStop) {
		event = m_stopEvent;
	} else if (evt == AcctAlert) {
		event = m_alertEvent;
	} else if (evt == AcctOn) {
		event = m_onEvent;
	} else if (evt == AcctOff) {
		event = m_offEvent;
	} else if (evt == AcctReject) {
		event = m_rejectEvent;
	}

	if (event.IsEmpty()) {
		PTRACE(1, "MQAcct\t" << GetName() << "Error: No message configured for event " << evt);
		return Fail;
	}

    std::map<PString, PString> params;
    SetupAcctParams(params, call, m_timestampFormat);
    event = ReplaceAcctParams(event, params);
    event = Toolkit::Instance()->ReplaceGlobalParams(event);

    return MQLog(event, m_callTopic);
}

GkAcctLogger::Status MQAcct::Log(GkAcctLogger::AcctEvent evt, const endptr & ep)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;

	if (!ep) {
		PTRACE(1, "MQAcct\t" << GetName() << " - missing endpoint info for event " << evt);
		return Fail;
	}

	PString event;
	if (evt == AcctRegister) {
		event = m_registerEvent;
	} else if (evt == AcctUnregister) {
		event = m_unregisterEvent;
	}

	if (event.IsEmpty()) {
		PTRACE(1, "MQAcct\t" << GetName() << "Error: No message configured for event " << evt);
		return Fail;
	}

    std::map<PString, PString> params;
    SetupAcctEndpointParams(params, ep, m_timestampFormat);
    event = ReplaceAcctParams(event, params);
    event = Toolkit::Instance()->ReplaceGlobalParams(event);

    return MQLog(event, m_regTopic);
}


#ifdef HAS_LIBMOSQUITTO

#include <mosquitto.h>

class MQTTAcct : public MQAcct
{
public:
	MQTTAcct(
		/// name from Gatekeeper::Acct section
		const char* moduleName,
		/// config section name to be used with an instance of this module,
		/// pass NULL to use a default section (named "moduleName")
		const char* cfgSecName = NULL
		);

	/// Destroy the accounting logger
	virtual ~MQTTAcct();

protected:
    virtual void Connect();
    virtual void Disconnect();
	virtual Status MQLog(const PString & event, const PString & routingKey);

private:
	MQTTAcct();
	/* No copy constructor allowed */
	MQTTAcct(const MQTTAcct &);
	/* No operator= allowed */
	MQTTAcct & operator=(const MQTTAcct &);

private:
    PString m_clientId;
    struct mosquitto * m_mosq;
};

MQTTAcct::MQTTAcct(const char* moduleName, const char* cfgSecName)
    : MQAcct(moduleName, cfgSecName)
{
	PConfig* cfg = GetConfig();
	const PString & cfgSec = GetConfigSectionName();

	PString port = cfg->GetString(cfgSec, "Port", "1883");  // different default
    port = Toolkit::Instance()->ReplaceGlobalParams(port);
    m_port = (WORD)port.AsUnsigned();
	m_callTopic = cfg->GetString(cfgSec, "CallTopic", "gnugk/call/status");
    m_callTopic = Toolkit::Instance()->ReplaceGlobalParams(m_callTopic);
	m_regTopic = cfg->GetString(cfgSec, "RegistrationTopic", "gnugk/registration/status");
    m_regTopic = Toolkit::Instance()->ReplaceGlobalParams(m_regTopic);
	m_clientId = cfg->GetString(cfgSec, "ClientId", "gnugk");

    Connect();
}

MQTTAcct::~MQTTAcct()
{
    Disconnect();
}

void MQTTAcct::Connect()
{
    PTRACE(3, "MQTTAcct\tConnecting to MQTT server " << m_host);
    mosquitto_lib_init();
    m_mosq = mosquitto_new((const char *)m_clientId, true, 0);
    if (m_mosq) {
        int rc = mosquitto_username_pw_set(m_mosq, m_user, m_password);
        rc = mosquitto_connect(m_mosq, m_host, m_port, 60);
        if (rc != MOSQ_ERR_SUCCESS) {
            PTRACE(1, "MQTTAcct\tError connecting to " << m_host << ":" << m_port);
        }
    } else {
        PTRACE(1, "MQTTAcct\tError initializing MQTT");
    }
}

void MQTTAcct::Disconnect()
{
    PTRACE(3, "MQTTAcct\tDisconnecting from MQTT server " << m_host);
    mosquitto_destroy(m_mosq);
    mosquitto_lib_cleanup();
}

GkAcctLogger::Status MQTTAcct::MQLog(const PString & event, const PString & topic)
{
    PTRACE(5, "MQTTAcct\tLogging message=" << event << " topic=" << topic);
    int rc = mosquitto_publish(m_mosq, NULL, (const char *)topic, event.GetLength(), (const char *)event, 0, false);

    if (rc == MOSQ_ERR_NO_CONN) {
        PTRACE(1, "MQTTAcct\tError publishing event: not connected (will re-try)");
        Disconnect();
        Connect();
        rc = mosquitto_publish(m_mosq, NULL, (const char *)topic, event.GetLength(), (const char *)event, 0, false);
    }
    if (rc != MOSQ_ERR_SUCCESS) {
        PTRACE(1, "MQTTAcct\tError publishing event: " << mosquitto_strerror(rc));
        return Fail;
    }

    return Ok;
}

namespace {
	// append accounting logger to the global list of loggers
	GkAcctLoggerCreator<MQTTAcct> MQTTAcctCreator("MQTTAcct");
}

#endif // HAS_LIBMOSQUITTO

////////////////////////////////////////////////////////////////////////

#ifdef HAS_LIBRABBITMQ

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>


class AMQPAcct : public MQAcct
{
public:
	AMQPAcct(
		/// name from Gatekeeper::Acct section
		const char* moduleName,
		/// config section name to be used with an instance of this module,
		/// pass NULL to use a default section (named "moduleName")
		const char* cfgSecName = NULL
		);

	/// Destroy the accounting logger
	virtual ~AMQPAcct();

protected:
    virtual void Connect();
    virtual void Disconnect();
	virtual Status MQLog(const PString & event, const PString & routingKey);

private:
	AMQPAcct();
	/* No copy constructor allowed */
	AMQPAcct(const AMQPAcct &);
	/* No operator= allowed */
	AMQPAcct & operator=(const AMQPAcct &);

private:
    PString m_exchange;
    PString m_routingKey;
    PString m_vhost;
    int m_channelID;
    PString m_contentType;
    amqp_socket_t * m_socket;
    amqp_connection_state_t m_conn;
	PMutex m_threadMutex;
};


AMQPAcct::AMQPAcct(const char* moduleName, const char* cfgSecName)
    : MQAcct(moduleName, cfgSecName)
{
	PConfig* cfg = GetConfig();
	const PString & cfgSec = GetConfigSectionName();

	m_exchange = cfg->GetString(cfgSec, "Exchange", "");
    m_exchange = Toolkit::Instance()->ReplaceGlobalParams(m_exchange);
	m_routingKey = cfg->GetString(cfgSec, "RoutingKey", "");
    m_routingKey = Toolkit::Instance()->ReplaceGlobalParams(m_routingKey);
    m_callTopic = m_routingKey;
    if (m_callTopic.IsEmpty())
        m_callTopic = "gnugk.call.status";
    m_regTopic = m_routingKey;
    if (m_regTopic.IsEmpty())
        m_regTopic = "gnugk.registration.status";
    m_vhost = cfg->GetString(cfgSec, "VHost", "/");
    m_vhost = Toolkit::Instance()->ReplaceGlobalParams(m_vhost);
	m_contentType = cfg->GetString(cfgSec, "ContentType", "text/plain");
	m_channelID = 1;

    Connect();
}

AMQPAcct::~AMQPAcct()
{
    Disconnect();
}

void AMQPAcct::Connect()
{
    PTRACE(3, "AMQPAcct\tConnecting to AMQP server " << m_host);
    m_socket = NULL;
	int status = 0;
	amqp_set_initialize_ssl_library(0); // don't init OpenSSL, GnuGk does it once for all modules
    m_conn = amqp_new_connection();
    if (m_useSSL) {
        m_socket = amqp_ssl_socket_new(m_conn);
        if (!m_socket) {
            PTRACE(1, "AMQPAcct\tError creating SSL socket");
        } else {
            if (!m_caCert.IsEmpty()) {
                status = amqp_ssl_socket_set_cacert(m_socket, (const char *)m_caCert);
                if (status) {
                    PTRACE(1, "AMQPAcct\tError setting CA certificate");
                }
            }
        }
    } else {
        m_socket = amqp_tcp_socket_new(m_conn);
        if (!m_socket) {
            PTRACE(1, "AMQPAcct\tError creating TCP socket");
        }
    }
    if (m_socket) {
        status = amqp_socket_open(m_socket, (const char*)m_host, m_port);
        if (status) {
            PTRACE(1, "AMQPAcct\tError opening socket to " << m_host << ":" << m_port);
        } else {
            amqp_rpc_reply_t r = amqp_login(m_conn, (const char*)m_vhost, 0, 131072, 0, AMQP_SASL_METHOD_PLAIN, (const char*)m_user, (const char*)m_password);
            if (r.reply_type != AMQP_RESPONSE_NORMAL) {
                PTRACE(1, "AMQPAcct\Error logging in: vhost=" << m_vhost << " user=" << m_user);
            } else {
                amqp_channel_open(m_conn, m_channelID);
                r = amqp_get_rpc_reply(m_conn);
                if (r.reply_type != AMQP_RESPONSE_NORMAL) {
                    PTRACE(1, "AMQPAcct\tError opening channel");
                }
            }
        }
    }
}

void AMQPAcct::Disconnect()
{
    PTRACE(3, "AMQPAcct\tDisconnecting from AMQP server " << m_host);
    if (m_socket) {
        (void)amqp_channel_close(m_conn, m_channelID, AMQP_REPLY_SUCCESS);
        (void)amqp_connection_close(m_conn, AMQP_REPLY_SUCCESS);
    }
    (void)amqp_destroy_connection(m_conn);
    m_socket = NULL; // free()ed by amqp_destroy_connection()
}

GkAcctLogger::Status AMQPAcct::MQLog(const PString & event, const PString & routingKey)
{
    PWaitAndSignal lock(m_threadMutex);

    PTRACE(5, "AMQPAcct\tLogging message=" << event << " routing key=" << routingKey);
    amqp_basic_properties_t props;
    props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.content_type = amqp_cstring_bytes((const char *)m_contentType);
    props.delivery_mode = 2; /* persistent delivery mode */
    int status = amqp_basic_publish(m_conn, m_channelID, amqp_cstring_bytes((const char *)m_exchange),
                                    amqp_cstring_bytes((const char *)routingKey), 0, 0,
                                    &props, amqp_cstring_bytes((const char *)event));
    if (status) {
        PTRACE(1, "AMQPAcct\tError publishing event: " << amqp_error_string2(status) << " (will re-try)");
        Disconnect();
        Connect();
        status = amqp_basic_publish(m_conn, m_channelID, amqp_cstring_bytes((const char *)m_exchange),
                                    amqp_cstring_bytes((const char *)routingKey), 0, 0,
                                    &props, amqp_cstring_bytes((const char *)event));
        if (status) {
            PTRACE(1, "AMQPAcct\tError publishing event: " << amqp_error_string2(status) << " (after re-try)");
            return Fail;
        } else {
            PTRACE(3, "AMQPAcct\tRe-try to publish event successful");
        }
    }

    return Ok;
}


namespace {
	// append accounting logger to the global list of loggers
	GkAcctLoggerCreator<AMQPAcct> AMQPAcctCreator("AMQPAcct");
}

#endif // HAS_LIBRABBITMQ
