//////////////////////////////////////////////////////////////////
//
// gk_const.h	constants for gatekeeper ports etc.
//
// Copyright (c) 2000-2010, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////


#ifndef GK_CONST_H
#define GK_CONST_H "@(#) $Id$"

#include "config.h"

/* all values can be set in the config file, section [Gatekeeper::<InstanceName>]
 * these are just the defaults
 */

#define GK_DEF_UNICAST_RAS_PORT		1719
#define GK_DEF_MULTICAST_PORT		1718
#define GK_DEF_MULTICAST_GROUP		"224.0.1.41"

/* port used by gatekeeper for routed signaling */
#define GK_DEF_CALL_SIGNAL_PORT		1720
#define GK_DEF_TLS_CALL_SIGNAL_PORT	1300

/* well known signal port */
#define GK_DEF_ENDPOINT_SIGNAL_PORT	1720

#define GK_DEF_STATUS_PORT			7000

#define GK_DEF_MULTIPLEX_H245_PORT  1722
#define GK_DEF_MULTIPLEX_RTP_PORT	3000
#define GK_DEF_MULTIPLEX_RTCP_PORT	3001

#define GK_DEF_LISTEN_QUEUE_LENGTH	1024

#define GK_DEF_BANDWIDTH			1280

const char * const H225_ProtocolIDv2 = "0.0.8.2250.0.2";

const char * const H225_ProtocolIDv4 = "0.0.8.2250.0.4";

const char * const H225_ProtocolIDv5 = "0.0.8.2250.0.5";

const char * const H225_ProtocolIDv6 = "0.0.8.2250.0.6";

const char * const H245_ProtocolIDv3 = "0.0.8.245.0.3";

const int MAX_H323_VERSION = 7;  // for messages we generate
const unsigned ProtocolID_BufferSize = 20;
extern char H225_ProtocolID[];
extern char H245_ProtocolID[];
extern const char *H225_Protocol_Version[];
extern const char *H245_Protocol_Version[];

//+++++++++++++++++++++++++++++++++++++++++++++
// GnuGk OID

#define GnuGkOID "1.3.6.1.4.1.27938"


//+++++++++++++++++++++++++++++++++++++++++++++
// ITU H.460 Standards

///////////////////////////////////////////
// H.460.18/.19
#ifdef HAS_H46018
static const char * const H46018_OID = "0.0.8.460.18.0.1";
static const char * const H46019_OID = "0.0.8.460.19.0.1";
#endif


///////////////////////////////////////////
// H.460.22
#define Std22_TLS				1	// detect TLS support
#define Std22_IPSec				2	// detect IPSec support
#define Std22_Priority			1	// priority
#define Std22_ConnectionAddress	2	// connectionAddress

///////////////////////////////////////////
// H.460.23

#define Std23_RemoteNAT			1	// bool if endpoint has remote NAT support
#define Std23_AnnexA			2	// bool Support Same NAT probing (Annex A)
#define Std23_IsNAT				3	// bool if endpoint is NATed
#define Std23_DetRASAddr		4	// Detected RAS H225_TransportAddress
#define Std23_STUNAddr			5	// transport IP address of STUN Server to test with
#define Std23_NATdet			6   // integer 8 Endpoint STUN detected NAT Type
#define Std23_AnnexB			7	// bool Support Proxy offload (Annex B)

//////////////////////////////////////////
// H.460.24

#define Std24_ProxyNAT			1	// bool Proxy for NAT support
#define Std24_RemoteNAT			2	// bool if endpoint has remote NAT support
#define Std24_MustProxy			3	// bool Media must proxy
#define Std24_IsNAT				4	// bool if endpoint is NATed
#define Std24_NATdet			5   // integer 8 Endpoint STUN detected NAT Type
#define Std24_SourceAddr		6	// transport Apparent public IP of remote
#define Std24_AnnexA			7	// bool Support Same NAT probing (Annex A)
#define Std24_NATInstruct		8	// integer 8 Instruction on how NAT is to be Traversed
#define Std24_AnnexB			9	// bool Support Proxy offload (Annex B)

#define GK_DEF_STUN_PORT		3478

#ifdef HAS_H46024A
static const char * const H46024A_OID = "0.0.8.460.24.1";
#endif
#ifdef HAS_H46024B
static const char * const H46024B_OID = "0.0.8.460.24.2";
#endif

//+++++++++++++++++++++++++++++++++++++++++++++
// Packetizer OID

///////////////////////////////////////////
// Presence

#define OID3 "1.3.6.1.4.1.17090.0.12"  // Presence v2+
#define OID3_PDU	1	// PASN_OctetString Presence PDU


//////////////////////////////////////////
// Registration Priority and Pre-Emption

#define OID6  "1.3.6.1.4.1.17090.0.6"  // Registration priority & pre-emption
#define OID6_Priority  1   // integer 8 Priority number highest priority gets registration
#define OID6_Preempt   2   // bool to instruct GK to preempt previous registration
#define OID6_PriNot    3   // bool to notify EP registration RRJ (priority) UCF (higher Priority)
#define OID6_PreNot    4   // bool to notify EP registration RRJ (can preempt) UCF (was preempted)


///////////////////////////////////////////
// Remote Vendor Information

#define OID9 "1.3.6.1.4.1.17090.0.9"  // Remote Vendor Information
#define VendorProdOID      1    // PASN_String of productID
#define VendorVerOID       2    // PASN_String of versionID


#endif
