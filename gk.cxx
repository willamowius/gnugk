//////////////////////////////////////////////////////////////////
//
// gk.cxx for GNU Gatekeeper
//
// Copyright (c) 2000-2018, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////


#include "config.h"
#include <ptlib.h>
#include <ptlib/sockets.h>
#ifndef _WIN32
#define HAS_SETUSERNAME
#include <signal.h>
#include <syslog.h>
#include <ptlib/syslog.h>
#endif
#ifdef P_LINUX
#include <sys/resource.h>
#include <sys/mman.h>
#endif
#ifndef _WIN32
#include <unistd.h>
#endif
#include <h225.h>
#include "h323util.h"
#include "Toolkit.h"
#include "stl_supp.h"
#include "RasSrv.h"
#include "RasTbl.h"
#include "ProxyChannel.h"
#include "GkStatus.h"
#include "SoftPBX.h"
#include "MakeCall.h"
#include "gktimer.h"
#include "gk.h"
#include "capctrl.h"
#include "snmp.h"

#ifdef HAS_LIBSSH
#include "libssh/libssh.h"
#endif


using std::vector;

PCREATE_PROCESS(Gatekeeper)

#if defined(_WIN32) && (_WIN32_WINNT >= WINDOWS_VISTA)
LPFN_WSASENDMSG g_pfWSASendMsg = NULL;
#endif

PTextFile* Gatekeeper::m_logFile = NULL;
PFilePath Gatekeeper::m_logFilename;
PMutex Gatekeeper::m_logFileMutex;
int Gatekeeper::m_rotateInterval = -1;
int Gatekeeper::m_rotateMinute = 0;
int Gatekeeper::m_rotateHour = 0;
int Gatekeeper::m_rotateDay = 0;
GkTimer* Gatekeeper::m_rotateTimer = GkTimerManager::INVALID_HANDLE;

const char * KnownConfigEntries[][2] = {
	// valid config entries
#ifdef HAS_DATABASE
	{ "AlternateGatekeepers::SQL", "CacheTimeout" },
	{ "AlternateGatekeepers::SQL", "ConnectTimeout" },
	{ "AlternateGatekeepers::SQL", "Database" },
	{ "AlternateGatekeepers::SQL", "Driver" },
	{ "AlternateGatekeepers::SQL", "Host" },
	{ "AlternateGatekeepers::SQL", "Library" },
	{ "AlternateGatekeepers::SQL", "MinPoolSize" },
	{ "AlternateGatekeepers::SQL", "Password" },
	{ "AlternateGatekeepers::SQL", "Query" },
	{ "AlternateGatekeepers::SQL", "ReadTimeout" },
	{ "AlternateGatekeepers::SQL", "Username" },
#ifdef HAS_LIBRABBITMQ
	{ "AMQPAcct", "AlertEvent" },
	{ "AMQPAcct", "CACert" },
	{ "AMQPAcct", "ConnectEvent" },
	{ "AMQPAcct", "ContentType" },
	{ "AMQPAcct", "Exchange" },
	{ "AMQPAcct", "Host" },
	{ "AMQPAcct", "OffEvent" },
	{ "AMQPAcct", "OnEvent" },
	{ "AMQPAcct", "Password" },
	{ "AMQPAcct", "Port" },
	{ "AMQPAcct", "RegisterEvent" },
	{ "AMQPAcct", "RejectEvent" },
	{ "AMQPAcct", "RoutingKey" },
	{ "AMQPAcct", "StartEvent" },
	{ "AMQPAcct", "StopEvent" },
	{ "AMQPAcct", "TimestampFormat" },
	{ "AMQPAcct", "UnregisterEvent" },
	{ "AMQPAcct", "User" },
	{ "AMQPAcct", "UseSSL" },
	{ "AMQPAcct", "UpdateEvent" },
	{ "AMQPAcct", "VHost" },
#endif // HAS_LIBRABBITMQ
	{ "AssignedAliases::SQL", "CacheTimeout" },
	{ "AssignedAliases::SQL", "ConnectTimeout" },
	{ "AssignedAliases::SQL", "Database" },
	{ "AssignedAliases::SQL", "Driver" },
	{ "AssignedAliases::SQL", "Host" },
	{ "AssignedAliases::SQL", "Library" },
	{ "AssignedAliases::SQL", "MinPoolSize" },
	{ "AssignedAliases::SQL", "Password" },
	{ "AssignedAliases::SQL", "Query" },
	{ "AssignedAliases::SQL", "ReadTimeout" },
	{ "AssignedAliases::SQL", "Username" },
	{ "AssignedGatekeepers::SQL", "CacheTimeout" },
	{ "AssignedGatekeepers::SQL", "ConnectTimeout" },
	{ "AssignedGatekeepers::SQL", "Database" },
	{ "AssignedGatekeepers::SQL", "Driver" },
	{ "AssignedGatekeepers::SQL", "Host" },
	{ "AssignedGatekeepers::SQL", "Library" },
	{ "AssignedGatekeepers::SQL", "MinPoolSize" },
	{ "AssignedGatekeepers::SQL", "Password" },
	{ "AssignedGatekeepers::SQL", "Query" },
	{ "AssignedGatekeepers::SQL", "ReadTimeout" },
	{ "AssignedGatekeepers::SQL", "Username" },
#ifdef HAS_LANGUAGE
	{ "AssignedLanguage::SQL", "CacheTimeout" },
	{ "AssignedLanguage::SQL", "ConnectTimeout" },
	{ "AssignedLanguage::SQL", "Database" },
	{ "AssignedLanguage::SQL", "Driver" },
	{ "AssignedLanguage::SQL", "Host" },
	{ "AssignedLanguage::SQL", "Library" },
	{ "AssignedLanguage::SQL", "MinPoolSize" },
	{ "AssignedLanguage::SQL", "Password" },
	{ "AssignedLanguage::SQL", "Query" },
	{ "AssignedLanguage::SQL", "ReadTimeout" },
	{ "AssignedLanguage::SQL", "Username" },
#endif
#endif
	{ "CTI::Agents", "CTI_Timeout" },	// obsolete, but still accepted
	{ "CTI::Agents", "RequestTimeout" },
	{ "CTI::Agents", "VirtualQueue" },	// obsolete, but still accepted
	{ "CTI::Agents", "VirtualQueueAliases" },
	{ "CTI::Agents", "VirtualQueuePrefixes" },
	{ "CTI::Agents", "VirtualQueueRegex" },
	{ "CTI::MakeCall", "Bandwidth" },
	{ "CTI::MakeCall", "DisableFastStart" }, // obsolete, but still accepted
	{ "CTI::MakeCall", "DisableH245Tunneling" },
	{ "CTI::MakeCall", "EndpointAlias" },
	{ "CTI::MakeCall", "Gatekeeper" },
	{ "CTI::MakeCall", "Interface" },
	{ "CTI::MakeCall", "UseH450" }, // obsolete, but still accepted
	{ "CTI::MakeCall", "TransferMethod" },
	{ "CallTable", "AcctUpdateInterval" },
	{ "CallTable", "DefaultCallDurationLimit" },
	{ "CallTable", "DefaultCallTimeout" },
	{ "CallTable", "DisabledCodecs" },
	{ "CallTable", "GenerateNBCDR" },
	{ "CallTable", "GenerateUCCDR" },
	{ "CallTable", "IRRCheck" },
	{ "CallTable", "IRRFrequency" },
	{ "CallTable", "SetCalledStationIdToDialedIP" },
	{ "CallTable", "SingleFailoverCDR" },
	{ "CallTable", "TimestampFormat" },
	{ "CallTable", "UseDestCallSignalIPAsDialedNumber" },
	{ "Endpoint", "Authenticators" },
	{ "Endpoint", "Discovery" },
	{ "Endpoint", "E164" },
#ifdef HAS_H46018
	{ "Endpoint", "EnableH46018" },
#endif
#ifdef HAS_H46023
	{ "Endpoint", "EnableH46023" },
#endif
	{ "Endpoint", "EnableGnuGkNATTraversal" },
	{ "Endpoint", "EndpointIdentifier" },
	{ "Endpoint", "ForwardDestIp" },
	{ "Endpoint", "Gatekeeper" },
	{ "Endpoint", "GatekeeperIdentifier" },
	{ "Endpoint", "H323ID" },
	{ "Endpoint", "HideGk" },
	{ "Endpoint", "NATKeepaliveInterval" },
	{ "Endpoint", "NATRetryInterval" },
	{ "Endpoint", "Password" },
	{ "Endpoint", "Prefix" },
	{ "Endpoint", "ProductId" },
	{ "Endpoint", "ProductVersion" },
	{ "Endpoint", "RRQRetryInterval" },
	{ "Endpoint", "EnableAdditiveRegistration" },
	{ "Endpoint", "TimeToLive" },
	{ "Endpoint", "Type" },
	{ "Endpoint", "UnregisterOnReload" },
#ifdef HAS_TLS
	{ "Endpoint", "UseTLS" },
#endif
	{ "Endpoint", "UseAlternateGK" },
	{ "Endpoint", "Vendor" },
	{ "FileAcct", "CDRString" },
	{ "FileAcct", "DetailFile" },
	{ "FileAcct", "Rotate" },
	{ "FileAcct", "RotateDay" },
	{ "FileAcct", "RotateTime" },
	{ "FileAcct", "StandardCDRFormat" },
	{ "FileAcct", "TimestampFormat" },
#ifdef HAS_LIBRABBITMQ
	{ "Gatekeeper::Acct", "AMQPAcct" },
#endif // HAS_LIBRABBITMQ
	{ "Gatekeeper::Acct", "CapacityControl" },
	{ "Gatekeeper::Acct", "FileAcct" },
#if defined (P_HTTP) || defined (HAS_LIBCURL)
	{ "Gatekeeper::Acct", "HttpAcct" },
#endif
	{ "Gatekeeper::Acct", "LuaAcct" },
	{ "Gatekeeper::Acct", "RadAcct" },
	{ "Gatekeeper::Acct", "SQLAcct" },
	{ "Gatekeeper::Acct", "StatusAcct" },
	{ "Gatekeeper::Acct", "SyslogAcct" },
	{ "Gatekeeper::Acct", "default" },
	{ "Gatekeeper::Auth", "AliasAuth" },
	{ "Gatekeeper::Auth", "CapacityControl" },
	{ "Gatekeeper::Auth", "FileIPAuth" },
	{ "Gatekeeper::Auth", "H350PasswordAuth" },
#if defined (P_HTTP) || defined (HAS_LIBCURL)
	{ "Gatekeeper::Auth", "HttpPasswordAuth" },
#endif // P_HTTP
#ifdef HAS_LUA
	{ "Gatekeeper::Auth", "LuaAuth" },
	{ "Gatekeeper::Auth", "LuaPasswordAuth" },
#endif
	{ "Gatekeeper::Auth", "PrefixAuth" },
	{ "Gatekeeper::Auth", "RadAliasAuth" },
	{ "Gatekeeper::Auth", "RadAuth" },
	{ "Gatekeeper::Auth", "SQLAliasAuth" },
	{ "Gatekeeper::Auth", "SQLAuth" },
	{ "Gatekeeper::Auth", "SQLPasswordAuth" },
	{ "Gatekeeper::Auth", "SimplePasswordAuth" },
	{ "Gatekeeper::Auth", "TwoAliasAuth" },
	{ "Gatekeeper::Auth", "default" },
	{ "Gatekeeper::Main", "AlternateGKs" },
	{ "Gatekeeper::Main", "Authenticators" },
	{ "Gatekeeper::Main", "Bind" },
	{ "Gatekeeper::Main", "CompareAliasCase" },
	{ "Gatekeeper::Main", "CompareAliasType" },
	{ "Gatekeeper::Main", "DefaultDomain" },
	{ "Gatekeeper::Main", "DisconnectCallsOnShutdown" },
#ifdef hasIPV6
	{ "Gatekeeper::Main", "EnableIPv6" },
#endif
	{ "Gatekeeper::Main", "EnableTTLRestrictions" },
	{ "Gatekeeper::Main", "EncryptAllPasswords" },
	{ "Gatekeeper::Main", "EndpointIDSuffix" },
	{ "Gatekeeper::Main", "EndpointSignalPort" },
	{ "Gatekeeper::Main", "EndpointSuffix" },
	{ "Gatekeeper::Main", "ExternalIP" },
	{ "Gatekeeper::Main", "ExternalIsDynamic" },
	{ "Gatekeeper::Main", "FortyTwo" },	// obsolete
	{ "Gatekeeper::Main", "FourtyTwo" },	// obsolete
	{ "Gatekeeper::Main", "Home" },
	{ "Gatekeeper::Main", "ListenQueueLength" },
	{ "Gatekeeper::Main", "MaxASNArraySize" },
	{ "Gatekeeper::Main", "MaxSocketQueue" },
	{ "Gatekeeper::Main", "MaxStatusClients" },
	{ "Gatekeeper::Main", "MaximumBandwidthPerCall" },
	{ "Gatekeeper::Main", "MinimumBandwidthPerCall" },
	{ "Gatekeeper::Main", "MinH323Version" },
	{ "Gatekeeper::Main", "MulticastGroup" },
	{ "Gatekeeper::Main", "MulticastPort" },
	{ "Gatekeeper::Main", "Name" },
	{ "Gatekeeper::Main", "NetworkInterfaces" },
	{ "Gatekeeper::Main", "RedirectGK" },
	{ "Gatekeeper::Main", "SendTo" },
	{ "Gatekeeper::Main", "SkipForwards" },
	{ "Gatekeeper::Main", "SshStatusPort" },
	{ "Gatekeeper::Main", "StatusEventBacklog" },
	{ "Gatekeeper::Main", "StatusEventBacklogRegex" },
	{ "Gatekeeper::Main", "StatusPort" },
	{ "Gatekeeper::Main", "StatusTraceLevel" },
	{ "Gatekeeper::Main", "TimeToLive" },
	{ "Gatekeeper::Main", "TimestampFormat" },
	{ "Gatekeeper::Main", "TotalBandwidth" },
	{ "Gatekeeper::Main", "TraceLevel" },
	{ "Gatekeeper::Main", "TTLExpireDropCall" },
	{ "Gatekeeper::Main", "UnicastRasPort" },
	{ "Gatekeeper::Main", "UseBroadcastListener" },
	{ "Gatekeeper::Main", "UseMulticastListener" },
	{ "Gatekeeper::Main", "WorkerThreadIdleTimeout" },
#ifdef HAS_GEOIP
	{ "GeoIPAuth", "AllowedCountries" },
	{ "GeoIPAuth", "Database" },
#endif
#ifdef H323_H350
	{ "GkH350::Settings", "AssignedAliases" },
	{ "GkH350::Settings", "BindAuthMode" },
	{ "GkH350::Settings", "BindUserDN" },
	{ "GkH350::Settings", "BindUserPW" },
	{ "GkH350::Settings", "GatekeeperDiscovery" },
	{ "GkH350::Settings", "SearchBaseDN" },
	{ "GkH350::Settings", "ServerName" },
	{ "GkH350::Settings", "ServerPort" },
	{ "GkH350::Settings", "ServiceControl" },
#ifdef hasLDAPStartTLS
	{ "GkH350::Settings", "StartTLS" },
#endif
#endif
#ifdef P_LDAP
	{ "GkLDAP::LDAPAttributeNames", "CallDestination" },
	{ "GkLDAP::LDAPAttributeNames", "H235PassWord" },
	{ "GkLDAP::LDAPAttributeNames", "H323ID" },
	{ "GkLDAP::LDAPAttributeNames", "IPAddress" },
	{ "GkLDAP::LDAPAttributeNames", "TelephonNo" },
	{ "GkLDAP::Settings", "BindAuthMode" },
	{ "GkLDAP::Settings", "BindUserDN" },
	{ "GkLDAP::Settings", "BindUserPW" },
	{ "GkLDAP::Settings", "SearchBaseDN" },
	{ "GkLDAP::Settings", "ServerName" },
	{ "GkLDAP::Settings", "ServerPort" },
	{ "GkLDAP::Settings", "sizelimit" },
#ifdef hasLDAPStartTLS
	{ "GkLDAP::Settings", "StartTLS" },
#endif
	{ "GkLDAP::Settings", "timelimit" },
#endif
#ifdef HAS_DATABASE
	{ "GkPresence::SQL", "CacheTimeout" },
	{ "GkPresence::SQL", "ConnectTimeout" },
	{ "GkPresence::SQL", "Database" },
	{ "GkPresence::SQL", "Driver" },
	{ "GkPresence::SQL", "Host" },
	{ "GkPresence::SQL", "IncrementalUpdate" },
	{ "GkPresence::SQL", "Library" },
	{ "GkPresence::SQL", "Password" },
	{ "GkPresence::SQL", "MinPoolSize" },
	{ "GkPresence::SQL", "QueryAdd" },
	{ "GkPresence::SQL", "QueryDelete" },
	{ "GkPresence::SQL", "QueryList" },
	{ "GkPresence::SQL", "QueryUpdate" },
	{ "GkPresence::SQL", "ReadTimeout" },
	{ "GkPresence::SQL", "UpdateWorkerTimer" },
	{ "GkPresence::SQL", "Username" },
#endif
	{ "GkQoSMonitor", "CallEndOnly" },
	{ "GkQoSMonitor", "DetailFile" },
	{ "GkQoSMonitor", "Enable" },
#ifdef HAS_DATABASE
	{ "GkQoSMonitor::SQL", "CacheTimeout" },
	{ "GkQoSMonitor::SQL", "ConnectTimeout" },
	{ "GkQoSMonitor::SQL", "Database" },
	{ "GkQoSMonitor::SQL", "Driver" },
	{ "GkQoSMonitor::SQL", "Host" },
	{ "GkQoSMonitor::SQL", "Library" },
	{ "GkQoSMonitor::SQL", "Password" },
	{ "GkQoSMonitor::SQL", "Query" },
	{ "GkQoSMonitor::SQL", "ReadTimeout" },
	{ "GkQoSMonitor::SQL", "Username" },
#endif
	{ "GkStatus::Filtering", "Enable" },
	{ "GkStatus::Filtering", "ExcludeFilter" },
	{ "GkStatus::Filtering", "IncludeFilter" },
	{ "GkStatus::Filtering", "NewRCFOnly" },
	{ "GkStatus::Message", "Compact" },
	{ "GkStatus::Message", "RCF" },
	{ "GkStatus::Message", "URQ" },
#ifdef H323_H235
	{ "H235", "CheckSendersID" },
	{ "H235", "FullQ931Checking" },
	{ "H235", "RequireGeneralID" },
	{ "H235", "TimestampGracePeriod" },
	{ "H235", "UseEndpointIdentifier" },
	{ "H235", "VerifyRandomNumber" },
#endif // H323_H235
#ifdef H323_H350
	{ "H350PasswordAuth", "PasswordTimeout" },
#endif
#if defined (P_HTTP) || defined (HAS_LIBCURL)
	{ "HttpAcct", "AlertBody" },
	{ "HttpAcct", "AlertURL" },
	{ "HttpAcct", "ConnectBody" },
	{ "HttpAcct", "ConnectURL" },
	{ "HttpAcct", "Method" },
	{ "HttpAcct", "OffBody" },
	{ "HttpAcct", "OffURL" },
	{ "HttpAcct", "OnBody" },
	{ "HttpAcct", "OnURL" },
	{ "HttpAcct", "RegisterBody" },
	{ "HttpAcct", "RegisterURL" },
	{ "HttpAcct", "RejectBody" },
	{ "HttpAcct", "RejectURL" },
	{ "HttpAcct", "StartBody" },
	{ "HttpAcct", "StartURL" },
	{ "HttpAcct", "StopBody" },
	{ "HttpAcct", "StopURL" },
	{ "HttpAcct", "UpdateBody" },
	{ "HttpAcct", "UpdateURL" },
	{ "HttpAcct", "TimestampFormat" },
	{ "HttpAcct", "UnregisterBody" },
	{ "HttpAcct", "UnregisterURL" },
	{ "HttpPasswordAuth", "Body" },
	{ "HttpPasswordAuth", "DeleteRegex" },
	{ "HttpPasswordAuth", "ErrorRegex" },
	{ "HttpPasswordAuth", "Method" },
	{ "HttpPasswordAuth", "PasswordTimeout" },
	{ "HttpPasswordAuth", "ResultRegex" },
	{ "HttpPasswordAuth", "URL" },
#endif // P_HTTP
#ifdef HAS_LUA
	{ "LuaAcct", "Script" },
	{ "LuaAcct", "ScriptFile" },
	{ "LuaAcct", "TimestampFormat" },
	{ "LuaAuth", "CallScript" },
	{ "LuaAuth", "CallScriptFile" },
	{ "LuaAuth", "RegistrationScript" },
	{ "LuaAuth", "RegistrationScriptFile" },
	{ "LuaPasswordAuth", "PasswordTimeout" },
	{ "LuaPasswordAuth", "Script" },
	{ "LuaPasswordAuth", "ScriptFile" },
#endif
	{ "LogFile", "DeleteOnRotation" },
	{ "LogFile", "Filename" },
#ifndef _WIN32
	{ "LogFile", "LogToSyslog" },
#endif
	{ "LogFile", "Rotate" },
	{ "LogFile", "RotateDay" },
	{ "LogFile", "RotateTime" },
	{ "PortNotifications", "H245PortOpen" },
	{ "PortNotifications", "H245PortClose" },
	{ "PortNotifications", "Q931PortOpen" },
	{ "PortNotifications", "Q931PortClose" },
	{ "PortNotifications", "RadiusPortOpen" },
	{ "PortNotifications", "RadiusPortClose" },
	{ "PortNotifications", "RASPortOpen" },
	{ "PortNotifications", "RASPortClose" },
	{ "PortNotifications", "RTPPortOpen" },
	{ "PortNotifications", "RTPPortClose" },
	{ "PortNotifications", "StatusPortOpen" },
	{ "PortNotifications", "StatusPortClose" },
	{ "PortNotifications", "T120PortOpen" },
	{ "PortNotifications", "T120PortClose" },
#ifdef HAS_H46018
	{ "Proxy", "AllowSignaledIPs" },
#endif
	{ "Proxy", "CheckH46019KeepAlivePT" },
	{ "Proxy", "DisableRTPQueueing" },
	{ "Proxy", "Enable" },
	{ "Proxy", "EnableRTCPStats" },
	{ "Proxy", "EnableRTPMute" },
	{ "Proxy", "ExplicitRoutes" },
#ifdef HAS_H46018
	{ "Proxy", "IgnoreSignaledIPs" },
	{ "Proxy", "IgnoreSignaledPrivateH239IPs" },
#endif
	{ "Proxy", "InternalNetwork" },
#ifdef HAS_H46018
	{ "Proxy", "LegacyPortDetection" },
#endif
	{ "Proxy", "ProxyAlways" },
	{ "Proxy", "ProxyForNAT" },
	{ "Proxy", "ProxyForSameNAT" },
	{ "Proxy", "RTPDiffServ" },
	{ "Proxy", "RTPInactivityCheck" },
	{ "Proxy", "RTPInactivityCheckSession" },
	{ "Proxy", "RTPInactivityTimeout" },
	{ "Proxy", "RTPMultiplexing" },
	{ "Proxy", "RTPMultiplexPort" },
	{ "Proxy", "RTCPMultiplexPort" },
	{ "Proxy", "RTPPortRange" },
	{ "Proxy", "RemoveMCInFastStartTransmitOffer" },
	{ "Proxy", "RestrictRTPSources" },
	{ "Proxy", "SearchBothSidesOnCLC" },
	{ "Proxy", "T120PortRange" },
	{ "RadAcct", "AppendCiscoAttributes" },
	{ "RadAcct", "DefaultAcctPort" },
	{ "RadAcct", "FixedUsername" },
	{ "RadAcct", "IdCacheTimeout" },
	{ "RadAcct", "LocalInterface" },
	{ "RadAcct", "RadiusPortRange" },
	{ "RadAcct", "RequestRetransmissions" },
	{ "RadAcct", "RequestTimeout" },
	{ "RadAcct", "RoundRobinServers" },
	{ "RadAcct", "Servers" },
	{ "RadAcct", "SharedSecret" },
	{ "RadAcct", "SocketDeleteTimeout" },
	{ "RadAcct", "TimestampFormat" },
	{ "RadAcct", "UseDialedNumber" },
	{ "RadAliasAuth", "AppendCiscoAttributes" },
	{ "RadAliasAuth", "DefaultAuthPort" },
	{ "RadAliasAuth", "FixedPassword" },
	{ "RadAliasAuth", "FixedUsername" },
	{ "RadAliasAuth", "IdCacheTimeout" },
	{ "RadAliasAuth", "IncludeTerminalAliases" },
	{ "RadAliasAuth", "LocalInterface" },
	{ "RadAliasAuth", "RadiusPortRange" },
	{ "RadAliasAuth", "RequestRetransmissions" },
	{ "RadAliasAuth", "RequestTimeout" },
	{ "RadAliasAuth", "RoundRobinServers" },
	{ "RadAliasAuth", "Servers" },
	{ "RadAliasAuth", "SharedSecret" },
	{ "RadAliasAuth", "SocketDeleteTimeout" },
	{ "RadAliasAuth", "UseDialedNumber" },
	{ "RadAliasAuth", "EmptyUsername" },
	{ "RadAuth", "AppendCiscoAttributes" },
	{ "RadAuth", "DefaultAuthPort" },
	{ "RadAuth", "IdCacheTimeout" },
	{ "RadAuth", "IncludeTerminalAliases" },
	{ "RadAuth", "LocalInterface" },
	{ "RadAuth", "RadiusPortRange" },
	{ "RadAuth", "RequestRetransmissions" },
	{ "RadAuth", "RequestTimeout" },
	{ "RadAuth", "RoundRobinServers" },
	{ "RadAuth", "Servers" },
	{ "RadAuth", "SharedSecret" },
	{ "RadAuth", "SocketDeleteTimeout" },
	{ "RadAuth", "UseDialedNumber" },
	{ "RasSrv::ARQFeatures", "ArjReasonRouteCallToGatekeeper" },
	{ "RasSrv::ARQFeatures", "CheckSenderIP" },
	{ "RasSrv::ARQFeatures", "LeastUsedRouting" },
	{ "RasSrv::ARQFeatures", "RemoveTrailingChar" },
	{ "RasSrv::ARQFeatures", "RoundRobinGateways" },
	{ "RasSrv::ARQFeatures", "SendRIP" },
	{ "RasSrv::LRQFeatures", "AcceptForwardedLRQ" },
	{ "RasSrv::LRQFeatures", "AcceptNonNeighborLCF" },
	{ "RasSrv::LRQFeatures", "AcceptNonNeighborLRQ" },
	{ "RasSrv::LRQFeatures", "AlwaysForwardLRQ" },
#ifdef HAS_LANGUAGE
	{ "RasSrv::LRQFeatures", "EnableLanguageRouting" },
#endif
	{ "RasSrv::LRQFeatures", "ForwardHopCount" },
	{ "RasSrv::LRQFeatures", "ForwardLRQ" },
	{ "RasSrv::LRQFeatures", "ForwardResponse" },
	{ "RasSrv::LRQFeatures", "LRQPingInterval" },
	{ "RasSrv::LRQFeatures", "NeighborTimeout" },
	{ "RasSrv::LRQFeatures", "PingAlias" },
	{ "RasSrv::LRQFeatures", "SendLRQPing" },
	{ "RasSrv::LRQFeatures", "SendRetries" },
	{ "RasSrv::LRQFeatures", "SendRIP" },
	{ "RasSrv::RRQFeatures", "AcceptEndpointIdentifier" },
	{ "RasSrv::RRQFeatures", "AcceptGatewayPrefixes" },
	{ "RasSrv::RRQFeatures", "AcceptMCUPrefixes" },
	{ "RasSrv::RRQFeatures", "AccHTTPLink" },
	{ "RasSrv::RRQFeatures", "AliasTypeFilter" },
	{ "RasSrv::RRQFeatures", "AuthenticatedAliasesOnly" },
	{ "RasSrv::RRQFeatures", "GatewayAssignAliases" },
	{ "RasSrv::RRQFeatures", "IRQPollCount" },
	{ "RasSrv::RRQFeatures", "OverwriteEPOnSameAddress" },
	{ "RasSrv::RRQFeatures", "SupportDynamicIP" },
#ifdef HAS_DATABASE
	{ "RewriteCLI::SQL", "CacheTimeout" },
	{ "RewriteCLI::SQL", "ConnectTimeout" },
	{ "RewriteCLI::SQL", "Database" },
	{ "RewriteCLI::SQL", "Driver" },
	{ "RewriteCLI::SQL", "Host" },
	{ "RewriteCLI::SQL", "InboundQuery" },
	{ "RewriteCLI::SQL", "Library" },
	{ "RewriteCLI::SQL", "MinPoolSize" },
	{ "RewriteCLI::SQL", "OutboundQuery" },
	{ "RewriteCLI::SQL", "Password" },
	{ "RewriteCLI::SQL", "ReadTimeout" },
	{ "RewriteCLI::SQL", "Username" },
#endif
	{ "RewriteSourceAddress", "ForceAliasType" },
	{ "RewriteSourceAddress", "MatchSourceTypeToDestination" },
	{ "RewriteSourceAddress", "OnlyE164" },
	{ "RewriteSourceAddress", "OnlyValid10Dand11D" },
	{ "RewriteSourceAddress", "ReplaceChar" },
	{ "RewriteSourceAddress", "Rules" },
	{ "RewriteSourceAddress", "TreatNumberURIDialedDigits" },
	{ "RoutedMode", "AcceptNeighborCalls" },
	{ "RoutedMode", "AcceptNeighborsCalls" },
	{ "RoutedMode", "AcceptUnregisteredCalls" },
	{ "RoutedMode", "ActivateFailover" },
	{ "RoutedMode", "AppendToCallingPartyNumberIE" },
	{ "RoutedMode", "AppendToDisplayIE" },
	{ "RoutedMode", "AlertingTimeout" },
	{ "RoutedMode", "AlwaysRewriteSourceCallSignalAddress" },
	{ "RoutedMode", "AutoProxyIPv4ToIPv6Calls" },
	{ "RoutedMode", "CallSignalHandlerNumber" },
	{ "RoutedMode", "CallSignalPort" },
	{ "RoutedMode", "CalledTypeOfNumber" },
	{ "RoutedMode", "CallingTypeOfNumber" },
	{ "RoutedMode", "CpsCheckInterval" },
	{ "RoutedMode", "CpsLimit" },
	{ "RoutedMode", "DisableFastStart" },
	{ "RoutedMode", "DisableGnuGkH245TcpKeepAlive" },
	{ "RoutedMode", "DisableH245Tunneling" },
	{ "RoutedMode", "DisableRetryChecks" },
	{ "RoutedMode", "DisableSettingUDPSourceIP" },
	{ "RoutedMode", "DropCallsByReleaseComplete" },
	{ "RoutedMode", "ENUMservers" },
	{ "RoutedMode", "EnableGnuGkTcpKeepAlive" },
#ifdef HAS_H235_MEDIA
	{ "RoutedMode", "EnableH235HalfCallMedia" },
	{ "RoutedMode", "EnableH235HalfCallMediaKeyUpdates" },
#endif
	{ "RoutedMode", "EnableH450.2" },
#ifdef HAS_H46017
	{ "RoutedMode", "EnableH46017" },
#endif
#ifdef HAS_H46018
	{ "RoutedMode", "EnableH46018" },
#endif
#ifdef HAS_H46023
	{ "RoutedMode", "EnableH46023" },
#endif
#ifdef HAS_H46026
	{ "RoutedMode", "EnableH46026" },
#endif
#ifdef HAS_H460P
	{ "RoutedMode", "EnableH460P" },
#endif
	{ "RoutedMode", "EnableGnuGkNATTraversal" },
	{ "RoutedMode", "FailoverCauses" },
	{ "RoutedMode", "FilterEmptyFacility" },
	{ "RoutedMode", "FilterVideoFastUpdatePicture" },
	{ "RoutedMode", "ForceNATKeepAlive" },
	{ "RoutedMode", "ForwardOnFacility" },
	{ "RoutedMode", "GKRouted" },
	{ "RoutedMode", "GenerateCallProceeding" },
	{ "RoutedMode", "GnuGkTcpKeepAliveInterval" },
	{ "RoutedMode", "GnuGkTcpKeepAliveMethodH225" },
	{ "RoutedMode", "GnuGkTcpKeepAliveMethodH245" },
#if defined(HAS_H235_MEDIA) && defined (HAS_SETTOKENLENGTH)
	{ "RoutedMode", "H235HalfCallMaxTokenLength" },
#endif
	{ "RoutedMode", "H225DiffServ" },
	{ "RoutedMode", "H245DiffServ" },
	{ "RoutedMode", "H245PortRange" },
	{ "RoutedMode", "H245Routed" },
	{ "RoutedMode", "H245TunnelingTranslation" },
	{ "RoutedMode", "H4502EmulatorTransferMethod" },
#ifdef HAS_H46018
	{ "RoutedMode", "H46018KeepAliveInterval" },
	{ "RoutedMode", "H46018NoNat" },
#endif
#ifdef HAS_H46023
	{ "RoutedMode", "H46023PublicIP" },
	{ "RoutedMode", "H46023SignalGKRouted" },
	{ "RoutedMode", "H46023STUN" },
	{ "RoutedMode", "H46024ForceDirect" },
	{ "RoutedMode", "H46023ForceNat" },
#endif
	{ "RoutedMode", "H460KeepAliveMethodH225" },
	{ "RoutedMode", "H460KeepAliveMethodH245" },
	{ "RoutedMode", "NATStdMin" },
	{ "RoutedMode", "PrependToCallingPartyNumberIE" },
	{ "RoutedMode", "ProxyHandlerHighPrio" },
	{ "RoutedMode", "Q931PortRange" },
	{ "RoutedMode", "RDSservers" },
	{ "RoutedMode", "RedirectCallsToGkIP" },
	{ "RoutedMode", "RemoveCallOnDRQ" },
	{ "RoutedMode", "RemoveFaxUDPOptionsFromRM" },
	{ "RoutedMode", "RemoveH235Call" },
	{ "RoutedMode", "RemoveH245AddressFromSetup" },
	{ "RoutedMode", "RemoveH245AddressOnTunneling" },
	{ "RoutedMode", "RemoveH460Call" },
	{ "RoutedMode", "RemoveSorensonSourceInfo" },
#ifdef HAS_H235_MEDIA
	{ "RoutedMode", "RequireH235HalfCallMedia" },
#endif
	{ "RoutedMode", "RtpHandlerNumber" },
	{ "RoutedMode", "ScreenCallingPartyNumberIE" },
	{ "RoutedMode", "ScreenDisplayIE" },
	{ "RoutedMode", "ScreenSourceAddress" },
	{ "RoutedMode", "SendReleaseCompleteOnDRQ" },
	{ "RoutedMode", "SetupTimeout" },
	{ "RoutedMode", "ShowForwarderNumber" },
	{ "RoutedMode", "SignalTimeout" },
	{ "RoutedMode", "SocketCleanupTimeout" },
	{ "RoutedMode", "SupportCallingNATedEndpoints" },
	{ "RoutedMode", "SupportNATedEndpoints" },
	{ "RoutedMode", "TcpKeepAlive" },
	{ "RoutedMode", "TLSCallSignalPort" },
	{ "RoutedMode", "TranslateFacility" },
	{ "RoutedMode", "TranslateReceivedQ931Cause" },
	{ "RoutedMode", "TreatUnregisteredNAT" },
	{ "RoutedMode", "TranslateSentQ931Cause" },
	{ "RoutedMode", "TranslateSorensonSourceInfo" },
	{ "RoutedMode", "UpdateCalledPartyToH225Destination" },
#ifdef HAS_H46026
	{ "RoutedMode", "UseH46026PriorityQueue" },
#endif
	{ "RoutedMode", "UseProvisionalRespToH245Tunneling" },
	{ "Routing::CatchAll", "CatchAllAlias" },
	{ "Routing::CatchAll", "CatchAllIP" },
	{ "Routing::DNS", "ResolveNonLocalLRQ" },
	{ "Routing::DNS", "RewriteARQDestination" },
	{ "Routing::ENUM", "ResolveLRQ" },
	{ "Routing::Forwarding", "CacheTimeout" },
	{ "Routing::Forwarding", "ConnectTimeout" },
	{ "Routing::Forwarding", "Database" },
	{ "Routing::Forwarding", "Driver" },
	{ "Routing::Forwarding", "Host" },
	{ "Routing::Forwarding", "Library" },
	{ "Routing::Forwarding", "MinPoolSize" },
	{ "Routing::Forwarding", "Password" },
	{ "Routing::Forwarding", "Query" },
	{ "Routing::Forwarding", "ReadTimeout" },
	{ "Routing::Forwarding", "Username" },
#ifdef HAS_LUA
	{ "Routing::Lua", "Script" },
	{ "Routing::Lua", "ScriptFile" },
#endif
	{ "Routing::NeighborSql", "CacheTimeout" },
	{ "Routing::NeighborSql", "ConnectTimeout" },
	{ "Routing::NeighborSql", "Database" },
	{ "Routing::NeighborSql", "Driver" },
	{ "Routing::NeighborSql", "Host" },
	{ "Routing::NeighborSql", "Library" },
	{ "Routing::NeighborSql", "MinPoolSize" },
	{ "Routing::NeighborSql", "Password" },
	{ "Routing::NeighborSql", "Query" },
	{ "Routing::NeighborSql", "ReadTimeout" },
	{ "Routing::NeighborSql", "Username" },
	{ "Routing::RDS", "ResolveLRQ" },
	{ "Routing::SRV", "ResolveNonLocalLRQ" },
#ifdef HAS_DATABASE
	{ "Routing::Sql", "CacheTimeout" },
	{ "Routing::Sql", "ConnectTimeout" },
	{ "Routing::Sql", "Database" },
	{ "Routing::Sql", "Driver" },
	{ "Routing::Sql", "EnableRegexRewrite" },
	{ "Routing::Sql", "Host" },
	{ "Routing::Sql", "Library" },
	{ "Routing::Sql", "MinPoolSize" },
	{ "Routing::Sql", "Password" },
	{ "Routing::Sql", "Query" },
	{ "Routing::Sql", "ReadTimeout" },
	{ "Routing::Sql", "Username" },
#endif
#ifdef HAS_SNMP
	{ "SNMP", "AllowRequestsFrom" },
	{ "SNMP", "AgentListenIP" },
	{ "SNMP", "AgentListenPort" },
	{ "SNMP", "EnableSNMP" },
	{ "SNMP", "Implementation" },
	{ "SNMP", "Standalone" },
	{ "SNMP", "TrapCommunity" },
	{ "SNMP", "TrapHost" },
#endif
#ifdef HAS_DATABASE
	{ "SQLAcct", "AlertQuery" },
	{ "SQLAcct", "CacheTimeout" },
	{ "SQLAcct", "ConnectTimeout" },
	{ "SQLAcct", "Database" },
	{ "SQLAcct", "Driver" },
	{ "SQLAcct", "Host" },
	{ "SQLAcct", "Library" },
	{ "SQLAcct", "MinPoolSize" },
	{ "SQLAcct", "OffQuery" },
	{ "SQLAcct", "OnQuery" },
	{ "SQLAcct", "Password" },
	{ "SQLAcct", "ReadTimeout" },
	{ "SQLAcct", "RegisterQuery" },
	{ "SQLAcct", "StartQuery" },
	{ "SQLAcct", "StartQueryAlt" },
	{ "SQLAcct", "StopQuery" },
	{ "SQLAcct", "StopQueryAlt" },
	{ "SQLAcct", "TimestampFormat" },
	{ "SQLAcct", "UnregisterQuery" },
	{ "SQLAcct", "UpdateQuery" },
	{ "SQLAcct", "Username" },
	{ "SQLAliasAuth", "CacheTimeout" },
	{ "SQLAliasAuth", "ConnectTimeout" },
	{ "SQLAliasAuth", "Database" },
	{ "SQLAliasAuth", "Driver" },
	{ "SQLAliasAuth", "Host" },
	{ "SQLAliasAuth", "Library" },
	{ "SQLAliasAuth", "MinPoolSize" },
	{ "SQLAliasAuth", "Password" },
	{ "SQLAliasAuth", "Query" },
	{ "SQLAliasAuth", "ReadTimeout" },
	{ "SQLAliasAuth", "Table" },
	{ "SQLAliasAuth", "Username" },
	{ "SQLAuth", "CacheTimeout" },
	{ "SQLAuth", "CallQuery" },
	{ "SQLAuth", "ConnectTimeout" },
	{ "SQLAuth", "Database" },
	{ "SQLAuth", "Driver" },
	{ "SQLAuth", "Host" },
	{ "SQLAuth", "Library" },
	{ "SQLAuth", "MinPoolSize" },
	{ "SQLAuth", "NbQuery" },
	{ "SQLAuth", "Password" },
	{ "SQLAuth", "ReadTimeout" },
	{ "SQLAuth", "RegQuery" },
	{ "SQLAuth", "Username" },
	{ "SQLConfig", "AssignedAliasQuery" },
	{ "SQLConfig", "CacheTimeout" },
	{ "SQLConfig", "ConfigQuery" },
	{ "SQLConfig", "ConnectTimeout" },
	{ "SQLConfig", "Database" },
	{ "SQLConfig", "Driver" },
	{ "SQLConfig", "GWPrefixesQuery" },
	{ "SQLConfig", "Host" },
	{ "SQLConfig", "Library" },
	{ "SQLConfig", "MinPoolSize" },
	{ "SQLConfig", "NeighborsQuery" },
	{ "SQLConfig", "NeighborsQuery2" },
	{ "SQLConfig", "Password" },
	{ "SQLConfig", "PermanentEndpointsQuery" },
	{ "SQLConfig", "ReadTimeout" },
	{ "SQLConfig", "RewriteAliasQuery" },
	{ "SQLConfig", "RewriteE164Query" },
	{ "SQLConfig", "Username" },
	{ "SQLPasswordAuth", "CacheTimeout" },
	{ "SQLPasswordAuth", "ConnectTimeout" },
	{ "SQLPasswordAuth", "Database" },
	{ "SQLPasswordAuth", "Driver" },
	{ "SQLPasswordAuth", "Host" },
	{ "SQLPasswordAuth", "Library" },
	{ "SQLPasswordAuth", "MinPoolSize" },
	{ "SQLPasswordAuth", "Password" },
	{ "SQLPasswordAuth", "Query" },
	{ "SQLPasswordAuth", "ReadTimeout" },
	{ "SQLPasswordAuth", "Username" },
#endif
	{ "StatusAcct", "ConnectEvent" },
	{ "StatusAcct", "RegisterEvent" },
	{ "StatusAcct", "StartEvent" },
	{ "StatusAcct", "StopEvent" },
	{ "StatusAcct", "TimestampFormat" },
	{ "StatusAcct", "UnregisterEvent" },
	{ "StatusAcct", "UpdateEvent" },
	{ "SyslogAcct", "ConnectEvent" },
	{ "SyslogAcct", "StartEvent" },
	{ "SyslogAcct", "StopEvent" },
	{ "SyslogAcct", "SyslogFacility" },
	{ "SyslogAcct", "SyslogLevel" },
	{ "SyslogAcct", "TimestampFormat" },
	{ "SyslogAcct", "UpdateEvent" },
#ifdef HAS_TLS
	{ "TLS", "CADir" },
	{ "TLS", "CAFile" },
	{ "TLS", "Certificates" },
	{ "TLS", "CheckCertificateIP" },
	{ "TLS", "CipherList" },
	{ "TLS", "EnableTLS" },
	{ "TLS", "Passphrase" },
	{ "TLS", "PrivateKey" },
	{ "TLS", "RequireRemoteCertificate" },
#endif

	// ignore name partially to check
	{ "EP::", "AddCallingPartyToSourceAddress" },
	{ "EP::", "AddNumbers" },
	{ "EP::", "AdditionalDestinationAlias" },
	{ "EP::", "CalledTypeOfNumber" },
	{ "EP::", "CallingTypeOfNumber" },
	{ "EP::", "Capacity" },
	{ "EP::", "DisableCallCreditCapabilities" },
	{ "EP::", "DisabledCodecs" },
#ifdef HAS_H46017
	{ "EP::", "DisableH46017" },
#endif
#ifdef HAS_H46018
	{ "EP::", "DisableH46018" },
#endif
	{ "EP::", "ForceGateway" },
	{ "EP::", "GatewayPrefixes" },
	{ "EP::", "GatewayPriority" },
	{ "EP::", "MaxBandwidth" },
	{ "EP::", "PrefixCapacities" },
	{ "EP::", "Proxy" },
	{ "EP::", "TranslateReceivedQ931Cause" },
	{ "EP::", "TranslateSentQ931Cause" },
#ifdef HAS_TLS
	{ "EP::", "UseTLS" },
#endif
	{ "Neighbor::", "AcceptForwardedLRQ" },
	{ "Neighbor::", "AcceptPrefixes" },
	{ "Neighbor::", "AuthUser" },
	{ "Neighbor::", "Dynamic" },
	{ "Neighbor::", "ForwardHopCount" },
	{ "Neighbor::", "ForwardLRQ" },
	{ "Neighbor::", "ForwardResponse" },
	{ "Neighbor::", "GatekeeperIdentifier" },
#ifdef HAS_H46018
	{ "Neighbor::", "H46018Client" },
	{ "Neighbor::", "H46018Server" },
#endif
	{ "Neighbor::", "Host" },
	{ "Neighbor::", "Password" },
	{ "Neighbor::", "SendAuthUser" },
	{ "Neighbor::", "SendIPs" },
	{ "Neighbor::", "SendLRQPing" },
	{ "Neighbor::", "SendPassword" },
	{ "Neighbor::", "SendPrefixes" },
#ifdef HAS_TLS
	{ "Neighbor::", "UseTLS" },
#endif

	// uncheckable sections
	{ "CapacityControl", "*" },
	{ "Endpoint::RewriteE164", "*" },
	{ "FileIPAuth", "*" },
	{ "GkStatus::Auth", "*" },
	{ "H225toQ931", "*" },
	{ "ModeSelection", "*" },
	{ "ModeVendorSelection", "*" },
	{ "NATedEndpoints", "*" },
	{ "PrefixAuth", "*" },
	{ "RasSrv::AlternateGatekeeper", "*" },
	{ "RasSrv::AssignedAlias", "*" },
	{ "RasSrv::AssignedGatekeeper", "*" },
	{ "RasSrv::GWPrefixes", "*" },
	{ "RasSrv::GWRewriteE164", "*" },
	{ "RasSrv::Neighbors", "*" },
	{ "RasSrv::PermanentEndpoints", "*" },
	{ "RasSrv::RRQAuth", "*" },
	{ "RasSrv::RewriteAlias", "*" },
	{ "RasSrv::RewriteE164", "*" },
	{ "ReplyToRasAddress", "*" },
	{ "RewriteCLI", "*" },
	{ "Routing::Explicit", "*" },
	{ "Routing::NumberAnalysis", "*" },
	{ "Routing::URIService", "*" },
	{ "RoutingPolicy", "*" },
	{ "RoutingPolicy::OnARQ", "*" },
	{ "RoutingPolicy::OnFacility", "*" },
	{ "RoutingPolicy::OnLRQ", "*" },
	{ "RoutingPolicy::OnSetup", "*" },
	{ "SimplePasswordAuth", "*" },
	{ "TwoAliasAuth", "*" },
	{ NULL }	// the end
};

namespace { // keep the global objects private

PTimedMutex ReloadMutex;

#ifndef _WIN32
PString pidfile("/var/run/gnugk.pid");
#endif

#ifdef P_LINUX
PString RlimAsString(unsigned long rlim_val)
{
	return (rlim_val == RLIM_INFINITY) ? PString("unlimited") : PString(rlim_val);

}
#endif

void ShutdownHandler()
{
	Gatekeeper::EnableLogFileRotation(false);
	// delete singleton objects
	PTRACE(3, "GK\tDeleting global reference tables");

	// end all calls before deleting handler objects (won't end calls if DisconnectCallsOnShutdown=0)
	CallTable::Instance()->ClearTable();

	Job::StopAll();
#ifdef HAS_H46018
	if (MultiplexedRTPHandler::InstanceExists())
		delete MultiplexedRTPHandler::Instance();
#endif
#ifdef HAS_H46026
	if (H46026RTPHandler::InstanceExists())
		delete H46026RTPHandler::Instance();
#endif
	if (CapacityControl::InstanceExists())
		delete CapacityControl::Instance();
	if (PreliminaryCallTable::InstanceExists())
		delete PreliminaryCallTable::Instance();
	if (CallTable::InstanceExists())
		delete CallTable::Instance();
	if (RegistrationTable::InstanceExists())
		delete RegistrationTable::Instance();
	if (RasServer::InstanceExists())
		delete RasServer::Instance();
	if (MakeCallEndPoint::InstanceExists())
		delete MakeCallEndPoint::Instance();
	if (Toolkit::InstanceExists())
		delete Toolkit::Instance();
#if defined(HAS_SNMP)
	DeleteSNMPAgent();
#endif
#ifdef HAS_LIBSSH
    ssh_finalize();
#endif

	PTRACE(3, "GK\tdelete ok");

	Gatekeeper::CloseLogFile();
}

bool CheckConfig(PConfig * cfg, const PString & mainsection)
{
	unsigned warnings = 0;
	bool mainsectionfound = false;
	PStringList sections = cfg->GetSections();
	for (PINDEX i = 0; i < sections.GetSize(); ++i) {
		// check section names
		PCaselessString sect = sections[i];
		PString fullSectionName = sections[i];
		if ((sect.Left(1) == ";") || (sect.Left(1) == "#")) {
			continue;
		}
		if (sect.Left(4) == "EP::") {
			sect = "EP::";
		}
		if (sect.Left(10) == "Neighbor::") {
			sect = "Neighbor::";
		}
		// strip off instance ID for routing sections
		if (sect.Left(9) == "Routing::" && sect.Find("::", 9) != P_MAX_INDEX) {
			sect = sect.Left(sect.Find("::", 9));
		}
		if (sect == mainsection) {
			mainsectionfound = true;
		}
		const char * ks = NULL;
		unsigned j = 0;
		bool found = false;
		bool section_checkable = true;
		while ((ks = KnownConfigEntries[j][0])) {
			if (sect == ks) {
				found = true;
				section_checkable = (PString(KnownConfigEntries[j][1]) != "*");
				break;
			}
			j++;
		}
		if (!found) {
			cerr << "WARNING: Config section [" << sect << "] unknown" << endl;
			PTRACE(0, "WARNING: Config section [" << sect << "] unknown");
			SNMP_TRAP(7, SNMPError, Configuration, "Config section [" + sect + "] unknown");
			warnings++;
		} else if (!section_checkable) {
			// section can't be checked in detail
		} else {
			// check all entries in this section
			PStringToString entries = cfg->GetAllKeyValues(fullSectionName);
			for (PINDEX j = 0; j < entries.GetSize(); j++) {
				PCaselessString key = entries.GetKeyAt(j);
				PString value = entries.GetDataAt(j);
				if (value.IsEmpty()) {
					PTRACE(2, "WARNING: Empty entry: [" << fullSectionName << "] " << key << "=");
				}
				unsigned k = 0;
				// allow Comment= in all sections
				bool entry_found = (key == "Comment");
				while ((ks = KnownConfigEntries[k][0]) && !entry_found) {
					const char * ke = KnownConfigEntries[k][1];
					k++;
					if ((sect == ks) && (key == ke)) {
						entry_found = true;
						break;
					}
				}
				if (!entry_found) {
					cerr << "WARNING: Config entry [" << fullSectionName << "] " << key << "=" << value << " unknown" << endl;
					PTRACE(0, "WARNING: Config entry [" << fullSectionName << "] " << key << "=" << value << " unknown");
					SNMP_TRAP(7, SNMPError, Configuration, "Config entry [" + fullSectionName + "] " + key + " unknown");
					warnings++;
				}
			}
		}
	}
	if (!mainsectionfound) {
		PTRACE(0, "WARNING: This doesn't look like a GNU Gatekeeper configuration file!");
		SNMP_TRAP(7, SNMPError, Configuration, "No config file");
	}

	return (warnings == 0);
}

// due to some unknown reason (PWLib bug?),
// we have to delete Toolkit::Instance first,
// or we get core dump
void ExitGK()
{
	Gatekeeper::EnableLogFileRotation(false);

	delete Toolkit::Instance();

	Gatekeeper::CloseLogFile();
	_exit(0);	// skip exit handlers: we know GnuGk couldn't start, so avoid crash in useless cleanup
}

} // end of anonymous namespace


#ifndef _WIN32
class GnuGkToSyslog : public PSystemLogToSyslog
{
public:
    GnuGkToSyslog();

    virtual void Output(PSystemLog::Level level, const char * msg);
};

GnuGkToSyslog::GnuGkToSyslog()
{
    openlog("GnuGk", LOG_PID, LOG_DAEMON);
}

void GnuGkToSyslog::Output(PSystemLog::Level level, const char * msg)
{
    PString syslogMsg(msg);
    // tabs get octal encoding in syslog, remove
    syslogMsg.Replace("\x09", " ", true);
    // make multi-line messages readable in syslog
    PStringArray lines = syslogMsg.Tokenise("\r\n", false);
    for (PINDEX i = 0; i < lines.GetSize(); ++i) {
        PSystemLogToSyslog::Output(level, lines[i]);
    }
}
#endif


void ReloadHandler()
{
	Gatekeeper::ReopenLogFile();

	// only one thread must do this
	if (ReloadMutex.Wait(0)) {
		/*
		** Enter critical Section
		*/
		ConfigReloadMutex.StartWrite();

		/*
		** Force reloading config
		*/
		Toolkit::Instance()->ReloadConfig();

		SoftPBX::TimeToLive = GkConfig()->GetInteger("TimeToLive", SoftPBX::TimeToLive);

		/*
		** Update all gateway prefixes
		*/

		CallTable::Instance()->LoadConfig();
		RegistrationTable::Instance()->LoadConfig();
		CallTable::Instance()->UpdatePrefixCapacityCounters();

		// don't put this in LoadConfig()
		RasServer::Instance()->SetRoutedMode();

		// Load ENUM servers
		RasServer::Instance()->SetENUMServers();

		// Load RDS servers
		RasServer::Instance()->SetRDSServers();

		RasServer::Instance()->LoadConfig();

		GkStatus::Instance()->LoadConfig();

		Gatekeeper::EnableLogFileRotation();

		ConfigReloadMutex.EndWrite();

		/*
		** Don't disengage current calls!
		*/
		PTRACE(3, "GK\tCarry on current calls.");

		SNMP_TRAP(3, SNMPInfo, General, "Full config reloaded");

		// give other threads the chance to pass by this handler
		PThread::Sleep(500);
		/*
		** Leave critical Section
		*/
		ReloadMutex.Signal();
	}
}

#ifdef _WIN32

BOOL WINAPI WinCtrlHandlerProc(DWORD dwCtrlType)
{
	PString eventName = "CTRL_UNKNOWN_EVENT";

	if (dwCtrlType == CTRL_LOGOFF_EVENT) {
		eventName = "CTRL_LOGOFF_EVENT";
		PTRACE(2, "GK\tGatekeeper received " << eventName);
		// prevent shut down
		return FALSE;
	}

	if (dwCtrlType == CTRL_C_EVENT)
		eventName = "CTRL_C_EVENT";
	else if (dwCtrlType == CTRL_BREAK_EVENT)
		eventName = "CTRL_BREAK_EVENT";
	else if (dwCtrlType == CTRL_CLOSE_EVENT)
		eventName = "CTRL_CLOSE_EVENT";
	else if (dwCtrlType == CTRL_SHUTDOWN_EVENT)
		eventName = "CTRL_SHUTDOWN_EVENT";

#ifndef hasPTLibTraceOnShutdownBug
	PTRACE(1, "GK\tGatekeeper shutdown due to " << eventName);
#endif

	PWaitAndSignal shutdown(ShutdownMutex);
	ShutdownFlag = true;
	RasServer::Instance()->Stop();

	// CTRL_CLOSE_EVENT:
	// this case needs special treatment as Windows would
	// immediately call ExitProcess() upon returning TRUE,
	// and the GK has no chance to clean-up. The call to
	// WaitForSingleObject() results in around 5 sec's of
	// clean-up time - This may at times not be sufficient
	// for the GK to shut down in an organized fashion. The
	// only safe way to handle this, is to remove the
	// 'Close' menu item from the System menu and we will
	// never have to deal with this event again.
	if (dwCtrlType == CTRL_CLOSE_EVENT)
		WaitForSingleObject(GetCurrentProcess(), 15000);

	// proceed with shut down
	return TRUE;
}

bool Gatekeeper::SetUserAndGroup(const PString & /*username*/)
{
	return false;
}

// method to enable data execution prevention when supported by OS (starting with XP SP3)
#define PROCESS_DEP_ENABLE                          0x00000001
#define PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION     0x00000002

BOOL SetDEP(__in DWORD dwFlags = PROCESS_DEP_ENABLE)
{
	HMODULE hMod = GetModuleHandleW(L"Kernel32.dll");
	if (!hMod)
		return FALSE;
	typedef BOOL (WINAPI *PSETDEP)(DWORD);
	PSETDEP procSet = (PSETDEP)GetProcAddress(hMod, "SetProcessDEPPolicy");
	if (!procSet)
		return FALSE;
	return procSet(dwFlags);
}

void InitializeRTPSending()
{
#if (_WIN32_WINNT >= WINDOWS_VISTA)
	// fetch function pointer for WSASendMsg function
	// this also servers as runtime check if the feature is available on the machine
	SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
	GUID WSASendMsgGuid = WSAID_WSASENDMSG;
	DWORD nbytes;
	int result;

	/* WSASendMsg(): Windows Vista / Windows Server 2008 and later */
	result = WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
						&WSASendMsgGuid, sizeof(WSASendMsgGuid),
						&g_pfWSASendMsg, sizeof(g_pfWSASendMsg), &nbytes, NULL, NULL);
	closesocket(s);
#endif
}

#else	// _WIN32

#include <pwd.h>

bool Gatekeeper::SetUserAndGroup(const PString & username)
{
#if defined(P_PTHREADS) && !defined(P_THREAD_SAFE_CLIB)
	static const size_t MAX_PASSWORD_BUFSIZE = 1024;

	struct passwd userdata;
	struct passwd *userptr;
	char buffer[MAX_PASSWORD_BUFSIZE];

#if defined (P_LINUX) || defined (P_AIX) || defined(P_IRIX) || (__GNUC__>=3 && defined(P_SOLARIS)) || defined(P_RTEMS)
	::getpwnam_r(username, &userdata, buffer, sizeof(buffer), &userptr);
#else
	userptr = ::getpwnam_r(username, &userdata, buffer, sizeof(buffer));
#endif
#else
	struct passwd *userptr = ::getpwnam(username);
#endif

	return userptr && userptr->pw_name
		&& (::setgid(userptr->pw_gid) == 0) && (::setuid(userptr->pw_uid) == 0);
}

void UnixShutdownHandler(int sig)
{
	if (RasServer::Instance()->IsRunning() && ShutdownMutex.Wait(0)) {
		ShutdownFlag = true;
		PTRACE(1, "GK\tReceived signal " << sig);
#ifdef HAS_H46017
		// unregister all H.460.17 endpoints before we stop the socket handlers and thus delete their sockets
		RegistrationTable::Instance()->UnregisterAllH46017Endpoints();
#endif
		PFile::Remove(pidfile);
		RasServer::Instance()->Stop();
	}
}

void UnixReloadHandler(int sig) // for HUP Signal
{
	PTRACE(1, "GK\tGatekeeper Hangup (signal " << sig << ")");
	ReloadHandler();
}

#ifdef P_LINUX
// dumping descriptor usage on Linux according to
// https://oroboro.com/file-handle-leaks-server/
void showFDInfo(int fd)
{
    PString msg;
    char buf[256];

    int fd_flags = fcntl( fd, F_GETFD );
    if ( fd_flags == -1) return;

    int fl_flags = fcntl( fd, F_GETFL );
    if (fl_flags == -1) return;

    char path[256];
    snprintf(path, sizeof(buf), "/proc/self/fd/%d", fd);

    memset(&buf[0], 0, sizeof(buf));
    ssize_t s = readlink( path, &buf[0], sizeof(buf));
    if (s == -1)
    {
        PTRACE(0, "GK\t(" << path << "): " << "not available");
        return;
    }
    msg = PString(fd) + " (" + buf + "): ";

    if (fd_flags & FD_CLOEXEC)  msg += "cloexec ";

    // file status
    if (fl_flags & O_APPEND  )  msg += "append ";
    if (fl_flags & O_NONBLOCK)  msg += "nonblock ";

    // acc mode
    if (fl_flags == O_RDONLY )  msg += "read-only ";
    if (fl_flags & O_RDWR    )  msg += "read-write ";
    if (fl_flags & O_WRONLY  )  msg += "write-only ";

    if (fl_flags & O_DSYNC   )  msg += "dsync ";
    if (fl_flags & O_RSYNC   )  msg += "rsync ";
    if (fl_flags & O_SYNC    )  msg += "sync ";

    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = 0;
    fl.l_start = 0;
    fl.l_len = 0;
    if (fcntl(fd, F_GETLK, &fl) == 0) {
        if (fl.l_type != F_UNLCK)
        {
            if (fl.l_type == F_WRLCK)
                msg += "write-locked";
            else
                msg += "read-locked";
            msg += "(pid:" + PString(fl.l_pid) + ") ";
        }
    }
    PTRACE(0, "GK\t" << msg);
}

void DumpDescriptorUsage(int sig)
{
    PTRACE(0, "GK\tSignal USR2 received: Printing descriptor usage");
    PTRACE(0, "GK\t----------------------------------------------------------------------");

    int numHandles = getdtablesize();
    unsigned used = 0;

    for (int i = 0; i < numHandles; i++)
    {
        int fd_flags = fcntl(i, F_GETFD);
        if (fd_flags == -1)
            continue;

        showFDInfo(i);
        used++;
    }
    PTRACE(0, "GK");
    PTRACE(0, "GK\t" << used << " descriptors used");
    PTRACE(0, "GK\t----------------------------------------------------------------------");
}
#endif // P_LINUX

#endif // not _WIN32


// default params for overwriting
Gatekeeper::Gatekeeper(const char * _manuf,
					   const char * _name,
					   WORD _majorVersion,
					   WORD _minorVersion,
					   CodeStatus _status,
					   WORD _buildNumber)
#ifdef COMPILE_AS_SERVICE
	: PServiceProcess(_manuf, _name, _majorVersion, _minorVersion, _status, _buildNumber)
#else
	: PProcess(_manuf, _name, _majorVersion, _minorVersion, _status, _buildNumber)
#endif
{
	m_strictConfigCheck = false;
#ifdef _WIN32
	// set data execution prevention (ignore if not available)
	SetDEP(PROCESS_DEP_ENABLE);
	InitializeRTPSending();	// check for Vista+ method
#endif

#ifdef COMPILE_AS_SERVICE
	// save original arguments
	for (int i = 0; i < GetArguments().GetCount(); i++) {
		savedArguments += GetArguments().GetParameter(i);
		savedArguments += " ";
	}
#ifndef _WIN32
	// set startup arguments for service process
	GetArguments().Parse(GetArgumentsParseString());
	if (GetArguments().HasOption("pid"))
		pidfile = GetArguments().GetOptionString("pid");
	GetArguments().SetArgs("-d -p " + pidfile);
#endif
#endif
#ifdef hasThreadAutoDeleteBug
	// work around a bug in PTLib 2.10.x that doesn't start the housekeeping thread to delete auto-delete threads
	SignalTimerChange();
#endif
}

#ifdef COMPILE_AS_SERVICE
PBoolean Gatekeeper::OnStart()
{
	// change to the default directory to the one containing the executable
	PDirectory exeDir = GetFile().GetDirectory();
	exeDir.Change();

	return TRUE;
}

void Gatekeeper::OnStop()
{
	Terminate();
}

void Gatekeeper::Terminate()
{
 	if (IsGatekeeperShutdown() || !RasServer::Instance()->IsRunning())
		return;
	PWaitAndSignal shutdown(ShutdownMutex);
	ShutdownFlag = true;
	RasServer::Instance()->Stop();
	// wait for termination
	PThread::Sleep(10 * 1000);	// sleep 10 sec
}

PBoolean Gatekeeper::OnPause()
{
	// ignore pause
	return false;	// return true; would pause, but we can't continue, then
}


void Gatekeeper::OnContinue()
{
	// ignore continue (can't be paused, anyway)
}

void Gatekeeper::OnControl()
{
}
#endif // COMPILE_AS_SERVICE


const PString Gatekeeper::GetArgumentsParseString() const
{
	return PString
		("r-routed."
		 "-h245routed."
		 "d-direct."
		 "l-timetolive:"
		 "b-bandwidth:"
		 "e-externalip:"
#ifdef HAS_SETUSERNAME
		 "u-user:"
#endif
		 "t-trace."
		 "o-output:"
		 "c-config:"
		 "s-section:"
		 "-pid:"
#ifdef P_LINUX
		 "-core:"
		 "-mlock."
#endif
		 "S-strict."
		 "h-help:"
		 );
}


bool Gatekeeper::InitHandlers(const PArgList & args)
{
#ifdef _WIN32
	SetConsoleCtrlHandler(WinCtrlHandlerProc, TRUE);
#else
	struct sigaction sigact;

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = UnixShutdownHandler;
	sigemptyset(&sigact.sa_mask);
	sigaddset(&sigact.sa_mask, SIGTERM);
	sigaddset(&sigact.sa_mask, SIGINT);
	sigaddset(&sigact.sa_mask, SIGQUIT);
	sigaddset(&sigact.sa_mask, SIGHUP);
	sigaddset(&sigact.sa_mask, SIGUSR1);

	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGQUIT, &sigact, NULL);

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = SIG_IGN;
	sigemptyset(&sigact.sa_mask);

	// ignore these signals
	sigaction(SIGPIPE, &sigact, NULL);
	sigaction(SIGABRT, &sigact, NULL);

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = UnixReloadHandler;
	sigemptyset(&sigact.sa_mask);
	sigaddset(&sigact.sa_mask, SIGHUP);
	sigaddset(&sigact.sa_mask, SIGUSR1);

	sigaction(SIGHUP, &sigact, NULL);
	sigaction(SIGUSR1, &sigact, NULL);

#ifdef P_LINUX
	// print descriptor usage on USR2
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = DumpDescriptorUsage;
	sigemptyset(&sigact.sa_mask);
	sigaddset(&sigact.sa_mask, SIGUSR2);

	sigaction(SIGUSR2, &sigact, NULL);
#endif

	if (args.HasOption("pid"))
		pidfile = args.GetOptionString("pid");
	PTextFile pid(pidfile, PFile::WriteOnly);
	pid.WriteLine(PString(PString::Unsigned, getpid()));
#endif
	return TRUE;
}

bool Gatekeeper::InitLogging(const PArgList & args)
{
	// Syslog is the default when compiled as service, but we don't want that
	PTrace::ClearOptions(PTrace::SystemLogStream | PTrace::Thread | PTrace::Timestamp);
	PTrace::SetOptions(PTrace::DateAndTime | PTrace::TraceLevel | PTrace::FileAndLine);
	PTrace::SetLevel(args.GetOptionCount('t'));
	if (args.HasOption('o')) {
		if (!SetLogFilename(args.GetOptionString('o'))) {
			cerr << "Warning: could not open the log file \""
			     << args.GetOptionString('o') << '"' << endl;
			return FALSE;
		}
	}
	return TRUE;
}


bool Gatekeeper::InitConfig(const PArgList & args)
{
	// get the name of the config file
	PFilePath fp;
	PString section("Gatekeeper::Main");

	if (args.HasOption('c'))
		fp = PFilePath(args.GetOptionString('c'));
	else
		fp = "gatekeeper.ini";
	if (!PFile::Exists(fp)) {
		cerr << "WARNING: Config file " << fp << " doesn't exist!"
			 << " Use the -c switch to specify the config file.\n" << endl;
	}

	if (args.HasOption('s'))
		section = args.GetOptionString('s');

	Toolkit::Instance()->SetConfig(fp, section);

	// check config for unknown options (only return failure when strict flag is set)
	return (CheckConfig(GkConfig(), section) || !m_strictConfigCheck);
}


void Gatekeeper::PrintOpts()
{
	cout << "Options:\n"
		"  -r  --routed       : Use gatekeeper routed call signaling\n"
		"  -rr --h245routed   : Use H.245 control channel routed\n"
		"  -d  --direct       : Use direct endpoint call signaling\n"
		"  -l  --timetolive n : Time to live for client registration\n"
		"  -b  --bandwidth n  : Specify the total bandwidth\n"
		"  -e  --externalip x.x.x.x : Specify the external IP\n"
#ifdef HAS_SETUSERNAME
		"  -u  --user name    : Run as this user\n"
#endif
		"  -t  --trace        : Set trace verbosity\n"
		"  -o  --output file  : Write trace to this file\n"
		"  -c  --config file  : Specify which config file to use\n"
		"  -s  --section sec  : Specify which main section to use in the config file\n"
		"      --pid file     : Specify the pid file\n"
#ifdef P_LINUX
		"      --core n       : Enable core dumps (with max size of n bytes)\n"
		"      --mlock        : Lock GnuGk into memory to prevent it being swapped out\n"
#endif
		"  -S  --strict       : Strict config check (don't start with errors in config)\n"
		"  -h  --help         : Show this message\n" << endl;
}


void Gatekeeper::Main()
{
#ifdef COMPILE_AS_SERVICE
	GetArguments().SetArgs(savedArguments);
#endif

	PArgList & args = GetArguments();
	args.Parse(GetArgumentsParseString());

#ifdef P_LINUX
	// set the core file size
	if (args.HasOption("core")) {
		PString msg;
		struct rlimit rlim;
		if (getrlimit(RLIMIT_CORE, &rlim) != 0) {
			msg = "Error: Could not get current core file size : error = " + PString(errno);
			cout << msg << endl;
			PTRACE(1, msg);
		} else {
			msg = "Current core dump size limits - soft: " + RlimAsString(rlim.rlim_cur) + ", hard: " + RlimAsString(rlim.rlim_max);
			cout << msg << endl;
			PTRACE(3, msg);
			int uid = geteuid();
			int result = seteuid(getuid()); // switch back to starting uid for next call
			if (result != 0) {
				PTRACE(1, "Warning: Setting EUID failed");
			}
			const PCaselessString s = args.GetOptionString("core");
			rlim_t v = (s == "unlimited" ? RLIM_INFINITY : (rlim_t)s.AsInteger());
			rlim.rlim_cur = v;
			if (rlim.rlim_max < rlim.rlim_cur)
				rlim.rlim_max = v;
			if (setrlimit(RLIMIT_CORE, &rlim) != 0) {
				msg = "Error: Could not set current core file size to " + RlimAsString(v) + " : error = " + PString(errno);
				cout << msg << endl;
				PTRACE(1, msg);
			} else {
				getrlimit(RLIMIT_CORE, &rlim);
				msg = "New core dump size limits - soft: " + RlimAsString(rlim.rlim_cur) + ", hard: " + RlimAsString(rlim.rlim_max);
				cout << msg << endl;
				PTRACE(3, msg);
			}
			result = seteuid(uid);
			if (result != 0) {
				PTRACE(1, "Warning: Setting EUID failed");
			}
		}
	}
	// lock in memory
	if (args.HasOption("mlock")) {
	    struct rlimit rlim;
	    rlim.rlim_max = RLIM_INFINITY;
	    rlim.rlim_cur = RLIM_INFINITY;
	    cout << "Trying to lock GnuGk into RAM" << endl;
	    PTRACE(1, "Trying to lock GnuGk into RAM");
	    if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
			cout << "setrlimit() failed: Not locking into RAM" << endl;
		    PTRACE(1, "setrlimit() failed: Not locking into RAM");
	    }
	    else {
			if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
				cout << "Cannot lock GnuGk into RAM, mlockall() failed" << endl;
			    PTRACE(1, "Cannot lock GnuGk into RAM, mlockall() failed");
			} else {
				cout << "GnuGk successfully locked into RAM" << endl;
			    PTRACE(1, "GnuGk successfully locked into RAM");
			}
	    }
	}
#endif

#ifdef HAS_SETUSERNAME
	if (args.HasOption('u')) {
		const PString username = args.GetOptionString('u');

		if (!SetUserAndGroup(username)) {
			cout << "GNU Gatekeeper could not run as user "
				<< username
				<< endl;
			return;
		}
	}
#endif

	if (!InitLogging(args))
		return;

	if (args.HasOption('h')) {
		PrintOpts();
		ExitGK();
	}

	// must be set very early before Toolkit gets instantiated and does IP detection
    PString externalIP;
    if (args.HasOption('e')) {
        externalIP = args.GetOptionString('e');
        if (IsIPAddress(externalIP)) {
            PTRACE(3, "External IP set to " << externalIP);
            Toolkit::Instance()->SetExternalIPFromCmdLine(externalIP);
        } else {
            PTRACE(2, "Invalid external IP: " << externalIP << " (ignored)");
        }
    }

	m_strictConfigCheck = args.HasOption('S');
	if (!InitConfig(args) || !InitHandlers(args)) {
		cerr << "ERROR: Serious error in the configuration - terminating" << endl;
		PTRACE(0, "ERROR: Serious error in the configuration - terminating");
		ExitGK();
	}

#ifndef _WIN32
    if (GkConfig()->GetBoolean("LogFile", "LogToSyslog", false)) {
        PTrace::SetOptions(PTrace::SystemLogStream);
        PTrace::SetStream(new PSystemLog(PSystemLog::Debug6)); // Debug6 = don't filter more than the global trace level
        PSystemLog::SetTarget(new GnuGkToSyslog());
        PSystemLog::GetTarget().SetThresholdLevel(PSystemLog::Debug6);
    }
#endif

	// set trace level + output file from config, if not set on the command line (for service)
	PString fake_cmdline;
	if (args.GetOptionCount('t') == 0) {
		int log_trace_level = GkConfig()->GetInteger("TraceLevel", 0);
		for (int t=0; t < log_trace_level; t++)
			fake_cmdline += " -t";
	}
	if (!args.HasOption('o')) {
		PString log_trace_file = GkConfig()->GetString("LogFile", "Filename", "");
		log_trace_file = Toolkit::Instance()->ReplaceGlobalParams(log_trace_file);
		if (!log_trace_file.IsEmpty())
			fake_cmdline += " -o " + log_trace_file;
	}
	if (!fake_cmdline.IsEmpty()) {
		for (int t = 0; t < args.GetOptionCount('t'); t++)
			fake_cmdline += " -t";
		PArgList fake_args(fake_cmdline);
		fake_args.Parse(GetArgumentsParseString());
		InitLogging(fake_args);
	}

	EnableLogFileRotation();

	PString welcome("GNU Gatekeeper with ID '" + Toolkit::GKName() + "' started\n" + Toolkit::GKVersion());
	cout << welcome << '\n';
	PTRACE(1, welcome);

#ifdef  _SC_NPROCESSORS_ONLN
    int nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs > 0) {
        PTRACE(1, "This server has " << nprocs << " CPU cores ("
            << GkConfig()->GetInteger(RoutedSec, "CallSignalHandlerNumber", 5) << " signal handling threads and "
            << GkConfig()->GetInteger(RoutedSec, "RtpHandlerNumber", 1) << " RTP threads configured)");
    }
#endif

	// PTLib 2.10.x provides meaningless value on Windows
	PTRACE(1, "Current file handle limit: " << PProcess::Current().GetMaxHandles());

#ifdef hasIPV6
	if (Toolkit::Instance()->IsIPv6Enabled()) {
		PTRACE(1, "IPv6 enabled");
		GNUGK_INADDR_ANY = PIPSocket::Address("::");
		PIPSocket::SetDefaultIpAddressFamily(AF_INET6);
	}
#endif

	vector<PIPSocket::Address> GKHome;
	PString home(Toolkit::Instance()->GetGKHome(GKHome));
	if (GKHome.empty()) {
		PTRACE(0, "Fatal: Cannot find any interface to run GnuGk!");
		cerr << "Fatal: Cannot find any interface to run GnuGk!\n";
		ExitGK();
	}
	cout << "Listen on " << home << "\n";

	PIPSocket::Address addr;
	if (Toolkit::Instance()->isBehindNAT(addr))
		cout << "Public IP: " << addr.AsString() << "\n\n";
	else
		cout << "\n";

	// Copyright notice
	cout <<
		"For documentation and updates please visit https://www.gnugk.org/.\n\n"
		"This program is free software; you can redistribute it and/or\n"
		"modify it under the terms of the GNU General Public License version 2.\n"
		"We also explicitly grant the right to link this code\n"
		"with the OpenH323/H323Plus and OpenSSL library.\n"
		<< endl;

#ifdef HAS_H46018
	cout << "This program contains H.460.18 and H.460.19 technology patented by Tandberg\n"
			"and licensed to the GNU Gatekeeper Project.\n"
			<< endl;
#endif

#ifdef HAS_H46023
	cout << "This program contains H.460.23 and H.460.24 technology\n"
            "licensed to the GNU Gatekeeper Project.\n"
		 << endl;
#endif

	// read capacity from commandline
	int GKcapacity;
	if (args.HasOption('b'))
		GKcapacity = args.GetOptionString('b').AsInteger();
	else
		GKcapacity = GkConfig()->GetInteger("TotalBandwidth", -1);
	if (GKcapacity == 0)
		GKcapacity = -1;	// turn bw management off for 0, too
	CallTable::Instance()->SetTotalBandwidth(GKcapacity);
	if (GKcapacity < 0)
		PTRACE(2, "GK\tTotal bandwidth not limited");
	else
		PTRACE(2, "GK\tAvailable bandwidth: " << GKcapacity);

	// read timeToLive from command line
	if (args.HasOption('l'))
		SoftPBX::TimeToLive = args.GetOptionString('l').AsInteger();
	else
		SoftPBX::TimeToLive = GkConfig()->GetInteger("TimeToLive", -1);
	PTRACE(2, "GK\tTimeToLive for Registrations: " << SoftPBX::TimeToLive);

	RasServer *RasSrv = RasServer::Instance();

	// read signaling method from commandline
	if (args.HasOption('r'))
		RasSrv->SetRoutedMode(true, (args.GetOptionCount('r') > 1 || args.HasOption("h245routed")));
	else if (args.HasOption('d'))
		RasSrv->SetRoutedMode(false, false);
#ifdef HAS_H235_MEDIA
    else if (Toolkit::Instance()->IsH235HalfCallMediaEnabled())
        RasSrv->SetRoutedMode(true, true);
#endif
	else
		RasSrv->SetRoutedMode();

	// Load ENUM servers
	RasSrv->SetENUMServers();

	// Load RDS servers
	RasSrv->SetRDSServers();

#ifdef HAS_SNMP
	if (Toolkit::Instance()->IsSNMPEnabled() && SelectSNMPImplementation() == "PTLib")
		SNMP_TRAP(1, SNMPInfo, General, "GnuGk started");	// when NOT registering as agent, send started trap here already
#endif

#ifdef P_SSL
    Toolkit::Instance()->InitOpenSSL(); // makes sure  OpenSSL gets initialized exactly once for the whole application
#endif // P_SSL

#ifdef HAS_LIBSSH
    if (ssh_init() < 0) {
        PTRACE(1, "ssh_init() failed");
        SNMP_TRAP(7, SNMPError, Network, "SSH init failed");
    }
#endif

#if defined(_WIN32)
	// 1) prevent CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT and CTRL_SHUTDOWN_EVENT
	//    dialog box from being displayed.
	// 2) set process shutdown priority - we want as much time as possible
	//    for tasks, such as unregistering endpoints during the shut down process.
	//    0x3ff is a maximum permitted for windows app
	SetProcessShutdownParameters(0x3ff, SHUTDOWN_NORETRY);
#endif

	// let's go
	RasSrv->Run();

	// graceful shutdown
	cerr << "\nShutting down gatekeeper . . . ";

	ShutdownHandler();
	cerr << "done\n";

#ifdef _WIN32
	// remove control handler/close console
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)WinCtrlHandlerProc, FALSE);
	FreeConsole();
#endif // _WIN32

#if defined(P_OPENBSD) || defined(P_NETBSD) || defined(P_MACOSX)
	_exit(0);	// skip exit handlers, will hang on OpenBSD 5.3, crash on NetBSD 7.0 and crash on MacOSX
#endif
}

namespace {
const char* const logConfigSectionName = "LogFile";
}

const char* const Gatekeeper::m_intervalNames[] =
{
	"Hourly", "Daily", "Weekly", "Monthly"
};

void Gatekeeper::GetRotateInterval(PConfig & cfg, const PString & section)
{
	PString s;

	if (m_rotateInterval == Hourly)
		m_rotateMinute = cfg.GetInteger(section, "RotateTime", 59);
	else {
		s = cfg.GetString(section, "RotateTime", "00:59");
		m_rotateHour = s.AsInteger();
		m_rotateMinute = 0;
		if (s.Find(':') != P_MAX_INDEX)
			m_rotateMinute = s.Mid(s.Find(':') + 1).AsInteger();

		if (m_rotateHour < 0 || m_rotateHour > 23 || m_rotateMinute < 0
			|| m_rotateMinute > 59) {
			PTRACEX(1, "GK\tInvalid log file RotateTime specified: " << s);
			m_rotateMinute = 59;
			m_rotateHour = 0;
		}
	}

	if (m_rotateInterval == Weekly)	{
		s = cfg.GetString(section, "RotateDay", "Sun");
		if (strspn(s, "0123456") == (size_t)s.GetLength()) {
			m_rotateDay = s.AsInteger();
		} else {
			std::map<PCaselessString, int> dayNames;
			dayNames["sun"] = 0; dayNames["sunday"] = 0;
			dayNames["mon"] = 1; dayNames["monday"] = 1;
			dayNames["tue"] = 2; dayNames["tuesday"] = 2;
			dayNames["wed"] = 3; dayNames["wednesday"] = 3;
			dayNames["thu"] = 4; dayNames["thursday"] = 4;
			dayNames["fri"] = 5; dayNames["friday"] = 5;
			dayNames["sat"] = 6; dayNames["saturday"] = 6;
			std::map<PCaselessString, int>::const_iterator i = dayNames.find(s);
			m_rotateDay = (i != dayNames.end()) ? i->second : -1;
		}
		if (m_rotateDay < 0 || m_rotateDay > 6) {
			PTRACEX(1, "GK\tInvalid log file RotateDay specified: " << s);
			m_rotateDay = 0;
		}
	} else if (m_rotateInterval == Monthly) {
		m_rotateDay = cfg.GetInteger(section, "RotateDay", 1);
		if (m_rotateDay < 1 || m_rotateDay > 31) {
			PTRACEX(1, "GK\tInvalid RotateDay specified: "
				<< cfg.GetString(section, "RotateDay", ""));
			m_rotateDay = 1;
		}
	}
}

void Gatekeeper::EnableLogFileRotation(bool enable)
{
	PWaitAndSignal lock(m_logFileMutex);

	if (m_rotateTimer != GkTimerManager::INVALID_HANDLE) {
		Toolkit::Instance()->GetTimerManager()->UnregisterTimer(m_rotateTimer);
		m_rotateTimer = GkTimerManager::INVALID_HANDLE;
	}

	if (!enable)
		return;

	PConfig * const config = GkConfig();
	// determine rotation type (by lines, by size, by time)
	const PString rotateCondition = config->GetString(logConfigSectionName, "Rotate", "").Trim();
	if (rotateCondition.IsEmpty())
		return;

	for (int i = 0; i < RotationIntervalMax; i++)
		if (strcasecmp(rotateCondition, m_intervalNames[i]) == 0)
			m_rotateInterval = i;

	if (m_rotateInterval < 0 || m_rotateInterval >= RotationIntervalMax) {
		PTRACEX(1, "GK\tUnsupported log file rotation method: " << rotateCondition << " - rotation disabled");
		return;
	}

	// time based rotation
	GetRotateInterval(*config, logConfigSectionName);

	// setup rotation timer in case of time based rotation
	PTime now, rotateTime;

	switch (m_rotateInterval)
	{
	case Hourly:
		rotateTime = PTime(0, m_rotateMinute, now.GetHour(), now.GetDay(),
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		if (rotateTime <= now)
			rotateTime += PTimeInterval(0, 0, 0, 1); // 1 hour
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			&Gatekeeper::RotateOnTimer, rotateTime, 60*60);
		PTRACEX(5, "GK\tHourly log file rotation enabled (first "
			"rotation scheduled at " << rotateTime);
		break;

	case Daily:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, now.GetDay(),
			now.GetMonth(), now.GetYear(), now.GetTimeZone());
		if (rotateTime <= now)
			rotateTime += PTimeInterval(0, 0, 0, 0, 1); // 1 day
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			&Gatekeeper::RotateOnTimer, rotateTime, 60*60*24);
		PTRACEX(5, "GK\tDaily rotation enabled (first rotation scheduled at " << rotateTime);
		break;

	case Weekly:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, now.GetDay(),
			now.GetMonth(), now.GetYear(), now.GetTimeZone()
			);
		if (rotateTime.GetDayOfWeek() < m_rotateDay)
			rotateTime += PTimeInterval(0, 0, 0, 0,
				m_rotateDay - rotateTime.GetDayOfWeek() /* days */
				);
		else if (rotateTime.GetDayOfWeek() > m_rotateDay)
			rotateTime -= PTimeInterval(0, 0, 0, 0,
				rotateTime.GetDayOfWeek() - m_rotateDay /* days */
				);
		if (rotateTime <= now)
			rotateTime += PTimeInterval(0, 0, 0, 0, 7); // 1 week
		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			&Gatekeeper::RotateOnTimer, rotateTime, 60*60*24*7
			);
		PTRACEX(5, "GK\tWeekly rotation enabled (first rotation scheduled at " << rotateTime);
		break;

	case Monthly:
		rotateTime = PTime(0, m_rotateMinute, m_rotateHour, 1,
			now.GetMonth(), now.GetYear(), now.GetTimeZone());
		rotateTime += PTimeInterval(0, 0, 0, 0, m_rotateDay - 1);
		while (rotateTime.GetMonth() != now.GetMonth())
			rotateTime -= PTimeInterval(0, 0, 0, 0, 1); // 1 day

		if (rotateTime <= now) {
			rotateTime = PTime(0, m_rotateMinute, m_rotateHour, 1,
				now.GetMonth() + (now.GetMonth() == 12 ? -11 : 1),
				now.GetYear() + (now.GetMonth() == 12 ? 1 : 0),
				now.GetTimeZone());
			const int month = rotateTime.GetMonth();
			rotateTime += PTimeInterval(0, 0, 0, 0, m_rotateDay - 1);
			while (rotateTime.GetMonth() != month)
				rotateTime -= PTimeInterval(0, 0, 0, 0, 1); // 1 day
		}

		m_rotateTimer = Toolkit::Instance()->GetTimerManager()->RegisterTimer(
			&Gatekeeper::RotateOnTimer, rotateTime);
		PTRACEX(5, "GK\tMonthly rotation enabled (first rotation scheduled at " << rotateTime);
		break;
	}
}

void Gatekeeper::RotateOnTimer(GkTimer* timer)
{
	m_logFileMutex.Wait();
	if (m_rotateInterval == Monthly) {
		// setup next time for one-shot timer
		const PTime& rotateTime = timer->GetExpirationTime();
		PTime newRotateTime(rotateTime.GetSecond(), rotateTime.GetMinute(),
			rotateTime.GetHour(), 1,
			rotateTime.GetMonth() < 12 ? rotateTime.GetMonth() + 1 : 1,
			rotateTime.GetMonth() < 12 ? rotateTime.GetYear() : rotateTime.GetYear() + 1,
			rotateTime.GetTimeZone());

		newRotateTime += PTimeInterval(0, 0, 0, 0, m_rotateDay - 1);

		const int month = newRotateTime.GetMonth();
		while (newRotateTime.GetMonth() != month)
			newRotateTime -= PTimeInterval(0, 0, 0, 0, 1); // 1 day

		timer->SetExpirationTime(newRotateTime);
		timer->SetFired(false);
	}
	m_logFileMutex.Signal();
	RotateLogFile();
}

bool Gatekeeper::SetLogFilename(const PString & filename)
{
	if (filename.IsEmpty())
		return false;

	PWaitAndSignal lock(m_logFileMutex);
	if (!m_logFilename && m_logFile != NULL && m_logFile->IsOpen() && m_logFilename == filename)
		return true;

	if (m_logFile) {
		PTRACEX(1, "GK\tLogging redirected to the file '" << filename << '\'');
		EnableLogFileRotation(false);
	}

	PTrace::SetStream(&cerr);

#ifndef hasDeletingSetStream
	delete m_logFile;
#endif
	m_logFile = NULL;

	m_logFilename = filename;
	m_logFile = new PTextFile(m_logFilename, PFile::WriteOnly, PFile::Create);
	if (!m_logFile->IsOpen()) {
		delete m_logFile;
		m_logFile = NULL;
		return false;
	}
	m_logFile->SetPosition(0, PFile::End);
	PTrace::SetStream(m_logFile);
	return true;
}

bool Gatekeeper::RotateLogFile()
{
	PWaitAndSignal lock(m_logFileMutex);

    if (GkConfig()->GetBoolean("LogFile", "LogToSyslog", false)) {
        return false;
    }

	if (m_logFile) {
		PTRACEX(1, "GK\tLogging closed (log file rotation)");
		PTrace::SetStream(&cerr); // redirect to cerr
#ifndef hasDeletingSetStream
		delete m_logFile;
#endif
		m_logFile = NULL;
	}

	if (m_logFilename.IsEmpty())
		return false;

	PFile* const oldLogFile = new PTextFile(m_logFilename, PFile::WriteOnly, PFile::MustExist);
	if (oldLogFile->IsOpen()) {
        if (GkConfig()->GetBoolean("LogFile", "DeleteOnRotation", false)) {
            oldLogFile->Close();
            oldLogFile->Remove(oldLogFile->GetFilePath());
        } else {
            // Backup of log file
            PFilePath filename = oldLogFile->GetFilePath();
            const PString timeStr = PTime().AsString("yyyyMMdd_hhmmss");
            const PINDEX lastDot = filename.FindLast('.');
            if (lastDot != P_MAX_INDEX)
                filename.Replace(".", "." + timeStr + ".", FALSE, lastDot);
            else
                filename += "." + timeStr;
            oldLogFile->Close();
            oldLogFile->Move(oldLogFile->GetFilePath(), filename);
		}
	}
	delete oldLogFile;

	m_logFile = new PTextFile(m_logFilename, PFile::WriteOnly, PFile::Create);
	if (!m_logFile->IsOpen()) {
		cerr << "Warning: could not open the log file \"" << m_logFilename << "\" after rotation" << endl;
		delete m_logFile;
		m_logFile = NULL;
		return false;
	}

	m_logFile->SetPosition(0, PFile::End);
	PTrace::SetStream(m_logFile);
	PTRACEX(1, "GK\tLogging restarted\n" + Toolkit::GKVersion());
	return true;
}

bool Gatekeeper::ReopenLogFile()
{
	PWaitAndSignal lock(m_logFileMutex);

    if (GkConfig()->GetBoolean("LogFile", "LogToSyslog", false)) {
        return false;
    }

	if (m_logFile) {
		PTRACEX(1, "GK\tLogging closed (reopen log file)");
		PTrace::SetStream(&cerr); // redirect to cerr
#ifndef hasDeletingSetStream
		delete m_logFile;
#endif
		m_logFile = NULL;
	}

	if (m_logFilename.IsEmpty())
		return false;

	m_logFile = new PTextFile(m_logFilename, PFile::WriteOnly,
		PFile::MustExist
		);
	if (!m_logFile->IsOpen()) {
		delete m_logFile;
		m_logFile = NULL;
	}

	if (m_logFile == NULL) {
		m_logFile = new PTextFile(m_logFilename, PFile::WriteOnly, PFile::Create);
		if (!m_logFile->IsOpen()) {
			cerr << "Warning: could not open the log file \"" << m_logFilename << "\" after rotation" << endl;
			delete m_logFile;
			m_logFile = NULL;
			return false;
		}
	}
	m_logFile->SetPosition(0, PFile::End);
	PTrace::SetStream(m_logFile);
	PTRACEX(1, "GK\tLogging restarted\n" + Toolkit::GKVersion());
	return true;
}

void Gatekeeper::CloseLogFile()
{
	PWaitAndSignal lock(m_logFileMutex);

	if (m_logFile) {
		PTRACEX(1, "GK\tLogging closed");
	}
	PTrace::SetStream(&cerr);
#ifndef hasDeletingSetStream
	delete m_logFile;
#endif
	m_logFile = NULL;
}
