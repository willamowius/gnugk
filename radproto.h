/*
 * radproto.h
 *
 * RADIUS protocol client classes that offer good performance,
 * scalability and multithreading access.
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 * Copyright (c) 2003-2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#if HAS_RADIUS

#ifndef __RADPROTO_H
#define __RADPROTO_H "@(#) $Id$"

#include <vector>
#include <ptlib/sockets.h>
#include "config.h"

class PRandom;
class PMessageDigest5;

/// Encapsulates RADIUS Attribute structure.
class RadiusAttr
{
public:
	friend class RadiusPDU;

	enum Constants {
		/// max length of the attribute raw data
		MaxLength = 255,
		/// length of the attribute fixed header (Type+Length)
		FixedHeaderLength = 2,
		/// max length of the Value field
		MaxValueLength = (MaxLength - FixedHeaderLength),
		/// length of the fixed header for VSA
		/// (standard header + VendorId field)
		VsaFixedHeaderLength = FixedHeaderLength + 4,
		/// max length of the VSA Value field
		VsaMaxValueLength = (MaxLength - VsaFixedHeaderLength),
		/// length of the fixed header for RFC2865 conformant VSA
		/// (standard header + VendorId, VendorType and VendorLength fields)
		VsaRfc2865FixedHeaderLength = VsaFixedHeaderLength + 2,
		/// max length of the VSA RFC2865 conformant Value field
		VsaMaxRfc2865ValueLength = (MaxLength - VsaRfc2865FixedHeaderLength)
	};

	/// Constants for RADIUS Attribute Type field
	enum AttrTypes {
		Invalid = 0, UserName, UserPassword, ChapPassword,
		NasIpAddress = 4, NasPort, ServiceType, FramedProtocol,
		FramedIpAddress = 8, FramedIpNetmask, FramedRouting, FilterId,
		FramedMtu = 12, FramedCompression, LoginIpHost, LoginService,
		LoginTcpPort = 16, OldPassword, ReplyMessage, CallbackNumber,
		CallbackId = 20, Expiration, FramedRoute, FramedIpxNet,
		State = 24, AttrTypeClass, VendorSpecific, SessionTimeout,
		IdleTimeout = 28, TerminationAction, CalledStationId, CallingStationId,
		NasIdentifier = 32, ProxyState, LoginLatService, LoginLatNode,
		LoginLatGroup = 36, FramedAppleTalkLink, FramedAppleTalkNetwork, FramedAppleTalkZone,
		AcctStatusType = 40, AcctDelayTime, AcctInputOctets, AcctOutputOctets,
		AcctSessionId = 44, AcctAuthentic, AcctSessionTime, AcctInputPackets,
		AcctOutputPackets = 48, AcctTerminateCause, AcctMultiSessionId, AcctLinkCount,
		AcctInputGigawords = 52, AcctOutputGigawords, EventTimestamp = 55,
		ChapChallenge = 60, NasPortType, PortLimit, LoginLatPort,
		TunnelType = 64, TunnelMediumType, TunnelClientEndpoint, TunnelServerEndpoint,
		AcctTunnelConnectionId = 68, TunnelPassword,
		PasswordRetry = 75,
		Prompt = 76, ConnectInfo, ConfigurationToken,
		AcctInterimInterval = 85, AcctTunnelPacketsLost, NasPortId,
		// RFC 3162
		NasIpv6Address = 95, FramedInterfaceId, FramedIpv6Prefix,
		LoginIpv6Host = 98, FramedIpv6Route, FramedIpv6Pool
	};

	/// Constants for Service-Type attribute values
	enum ServiceTypes {
		ST_Login = 1, ST_Framed, ST_CallbackLogin,
		ST_CallbackFramed = 4, ST_Outbound, ST_Administrative,
		ST_NasPrompt = 7,
		ST_AuthenticateOnly = 8, ST_CallbackNasPrompt, ST_CallCheck,
		ST_CallbackAdministrative = 9
	};

	/// Constants for Framed-Protocol attribute values
	enum FramedProtocols {
		FP_Ppp = 1,
		FP_Slip
	};

	/// Constants for Framed-Compression attribute values
	enum FramedCompressionTypes {
		FC_None = 0,
		FC_VJTcpIp,
		FC_Ipx,
		FC_StacLZS
	};

	/// Constants for Login-Service attribute values
	enum LoginServiceTypes {
		LS_Telnet = 0, LS_Rlogin, LS_TcpClear, LS_PortMaster,
		LS_Lat, LS_X25_PAD, LS_X25_T3POS, LS_TcpClearQuiet
	};

	/// Constants for NAS-Port-Type attribute values
	enum NASPortTypes {
		NasPort_Asynchronous = 0, NasPort_Synchronous, NasPort_IsdnSynchronous,
		NasPort_IsdnAsynchronousV120 = 3, NasPort_IsdnAsynchronousV110,
		NasPort_Virtual = 5, NasPort_Piafs, NasPort_HdlcClearChannel,
		NasPort_X25 = 8, NasPort_X75, NasPort_G3Fax, NasPort_SDSL,
		NasPort_AdslCap = 12, NasPort_AdslDmt, NasPort_Idsl, NasPort_Ehternet,
		NasPort_xDsl = 16, NasPort_Cable, NasPort_WirelessOther,
		NasPort_WirelessIeee8021 = 19
	};

	/// Constants for Acct-Status-Type atribute values
	enum AcctStatusTypes {
		AcctStatus_Start = 1,
		AcctStatus_Stop = 2,
		AcctStatus_InterimUpdate = 3,
		AcctStatus_AccountingOn = 7,
		AcctStatus_AccountingOff = 8
	};

	/// Constants for VendorId VSA field
	enum VendorIdentifiers {
		CiscoVendorId = 9
	};

	/// Constants for Cisco VSA types
	enum CiscoVSA {
		CiscoVSA_AV_Pair = 1,
		CiscoVSA_h323_remote_address = 23, CiscoVSA_h323_conf_id = 24,
		CiscoVSA_h323_setup_time = 25, CiscoVSA_h323_call_origin = 26,
		CiscoVSA_h323_call_type = 27, CiscoVSA_h323_connect_time = 28,
		CiscoVSA_h323_disconnect_time = 29, CiscoVSA_h323_disconnect_cause = 30,
		CiscoVSA_h323_voice_quality = 31, CiscoVSA_h323_gw_id = 33,
		CiscoVSA_h323_incoming_conf_id = 35,

		CiscoVSA_h323_credit_amount = 101, CiscoVSA_h323_credit_time = 102,
		CiscoVSA_h323_return_code = 103, CiscoVSA_h323_redirect_number = 106,
		CiscoVSA_h323_preferred_lang = 107,
		CiscoVSA_h323_redirect_ip_address = 108,
		CiscoVSA_h323_billing_model = 109, CiscoVSA_h323_currency = 110,
		CiscoVSA_release_source = 115, CiscoVSA_preferred_codec = 116,
		CiscoVSA_rewritten_e164_num = 117
	};

	/** Construct uninitialized attribute. It should be initialized
		later by other means (operator=, etc.)
	*/
	RadiusAttr();

	/** Create TLV RADIUS attribute of a given type,
		initializing #value# field with 'attrLength' bytes
		of data pointed to by 'attrValue'. In case of VSA,
		#vsaVendorId# is read from the attribute's value data.
	*/
	RadiusAttr(
		unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
		const void* attrValue, /// buffer with attribute Value data
		PINDEX valueLength /// length of attribute Value data
		);

	/** Copy constructor for RADIUS Attribute. It simply does byte copy.
	*/
	RadiusAttr(
		const RadiusAttr & attr /// attribute to copy from
		) { memcpy(m_data, attr.m_data, attr.m_length); }

	/** Create TLV RADIUS attribute of a given type,
		initializing #value# field with 'stringValue.GetLength()' bytes
		from 'stringValue' string. In case of VSA,
		#vsaVendorId# is extracted from data contained in the #value# field.
	*/
	RadiusAttr(
		unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
		const PString & stringValue /// string to be stored in the attribute Value data
		);

	/** Create TLV RADIUS attribute of a given type,
		initializing #value# field with an integer value passed
		with 'intValue' parameter. This constructor should be also used
		for attributes carrying 32-bit timestamps.
	*/
	RadiusAttr(
		unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
		int intValue /// 32 bit integer to be stored in the attribute Value
		);

	/** Create TLV RADIUS attribute of a given type,
		initializing #value# field with 32 bit IPv4 or 128 bit IPv6 address
		value passed with 'addressValue' parameter.
	*/
	RadiusAttr(
		unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
		const PIPSocket::Address & addressValue /// IP address to be stored in the attribute Value
		);

	/** Create TLV RADIUS vendor-specific (26) attribute of a given
		vendor specific type, initializing #value# data with 'vendorId'
		32 bit identifier, 'vendorType' vendor attribute type
		and 'attrLength' bytes of data pointer to by 'attrValue'.
		#vsaVendorId# is set to 'vendorId'.
	*/
	RadiusAttr(
		const void* attrValue, /// buffer with data to be stored in the attribute Value
		PINDEX valueLength, /// data length (bytes)
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
		);

	/** Create TLV RADIUS vendor-specific attribute of a given type,
		initializing #value# data with 'vendorId' 32 bit identifier,
		'vendorType' vendor attribute type
		and 'stringValue.GetLength()' bytes (characters) of 'stringValue'
		parameter. #vsaVendorId# is set to 'vendorId'.
	*/
	RadiusAttr(
		const PString & stringValue, /// string to be stored in the attribute Value
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
		);

	/** Create TLV RADIUS vendor-specific attribute of a given type,
		initializing #value# data with 'vendorId' 32 bit identifier,
		'vendorType' vendor-specific attribute type
		and 32 bit 'intValue' integer value. #vsaVendorId# is set to 'vendorId'.
	*/
	RadiusAttr(
		int intValue, /// 32 bit integer to be stored in the attribute Value
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
		);

	/** Create TLV RADIUS vendor-specific attribute of a given type,
		initializing #value# data with 'vendorId' 32 bit identifier,
		'vendorType' vendor-specific attribute type
		and 32 bit IPv6 address specified by 'addressValue' parameter.
		#vsaVendorId# is set to 'vendorId'.
	*/
	RadiusAttr(
		const PIPSocket::Address & addressValue, /// IP address to be stored in the attribute Value
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
		);

	/** Create TLV RADIUS Cisco VSA attribute of a given type. If #vsaHack#
	    is false, then the attribute name is also embedded into the attribute
	    value (like 'h323-currency=USD').
	*/
	RadiusAttr(
		unsigned char type, /// Cisco-specific attribute type
		bool vsaHack, /// true to not prepend attribute name to its value
		const PString & stringValue /// string to be stored in the attribute Value
		);

	/** Create TLV RADIUS attribute, reading raw data from the buffer
	specified by 'rawData' parameter. Reading stops after full attribute
	is reconstructed from the data or 'rawLength' bytes have been read.
	Make sure to call #IsValid()# to check if the attribute has been
	reconstructed successfully. Call #GetLength()# to obtain number of bytes
	that have been actually read.
	*/
	RadiusAttr(
		const void* rawData, /// buffer with the attribute raw data
		PINDEX rawLength /// length (bytes) of the buffer
		);

	/** @return
		Type of this attribute (see #enum AttrTypes#).
	*/
	unsigned char GetType() const { return m_type; }

	/** @return
		Vendor-specific type for this attribute, assuming this
		attribute is a VSA that conforms to RFC 2865 guidelines for VSAs
		(has vendorId, vendorType and vendorLength fields).
	*/
	unsigned char GetVsaType() const { return (m_length < VsaRfc2865FixedHeaderLength) ? 0 : m_vendorType; }

	/** @return
		Total length (bytes) of this attribute.
	*/
	PINDEX GetLength() const { return m_length; }

	/** @return
		Length of the Value field for this attribute.
	*/
	PINDEX GetValueLength() const
	{
		const PINDEX len = m_length;
		const PINDEX headerLen = IsVsa() ? VsaFixedHeaderLength : FixedHeaderLength;

		return (len <= headerLen) ? 0 : (len - headerLen);
	}

	/** @return
		Length (bytes) of the Value field for this attribute,
		assuming that it conforms to RFC 2865 guidelines for VSAs
		(contains vendorId, vendorType and vendorLength fields).
	*/
	PINDEX GetVsaValueLength() const;

	/** Fill the byte array with Value associated with this attribute.
		The array is resized, if necessary, to contain the value.
		Call #GetValueLength()# to determine number of bytes written
		to the array
	*/
	bool GetValue(
		PBYTEArray & val, /// array where data is to be stored
		PINDEX offset = 0 /// offset into the array, where the data write starts
		) const;

	/** Fill the byte array with Value associated with this attribute,
		assuming that this attribute is RFC 2865 guidelines conformant VSA.
		The array is resized, if necessary, to contain the value.
		Call #GetVsaValueLength()# to determine number of bytes written
		to the array
	*/
	bool GetVsaValue(
		PBYTEArray & val, /// array where data is to be stored
		PINDEX offset = 0 /// offset into the array, where the data write starts
		) const;

	/** @return
		True if this is a vendor-specific attribute (VSA).
	*/
	bool IsVsa() const { return (m_type == VendorSpecific); }

	/** @return
		32 bit vendor identifier for VSA. This call is valid only
		for VSA attributes (see #IsVSA()#). Also ensure that this attribute
		is valid (#IsValid()).
	*/
	int GetVsaVendorId() const;

	/** Get attribute Value as a string. Be aware that the string
		may contain embedded 0s. For VSA attributes this call will
		build the string from data contained after vendorId field.
		If RFC 2865 guidelines conformant VSA value is to be retrieved
		use rather #AsVsaString()#.

		@return
		PString containing attribute Value.
		If an error occurs an empty string is returned.
	*/
	PString AsString() const;

	/** Get RFC 2865 guidelines conformant VSA Value as a string.
		Be aware that the string may contain embedded 0s. This call will
		build the string from data contained after vendorId, vendorType and
		vendorLength fields.

		@return
		PString containing attribute Value.
		If an error occurs an empty string is returned.
	*/
	PString AsVsaString() const;

	/** Get Cisco's VSA value as a string, with attribute name removed,
	    if it is prepended to the string.

		@return
		PString containing attribute Value.
	*/
	PString AsCiscoString() const;

	/** Get attribute Value as a 32 bit integer.
		For VSA attributes this call will build the integer
		from 4 bytes of data contained after vendorId field.
		If RFC 2865 guidelines conformant VSA value is to be retrieved
		use rather #AsVsaInteger()#.

		@return
		An integer representing attribute Value.
		If an error occurs 0 is returned.
	*/
	int AsInteger() const;

	/** Get RFC 2865 guidelines conformant VSA Value as a 32 bit integer.
		This call will build the integer from 4 bytes of data contained
		after vendorId, vendorType and vendorLength fields.

		@return
		An integer representing attribute Value.
		If an error occurs 0 is returned.
	*/
	int AsVsaInteger() const;

	/** Get attribute Value as a 32 bit timestamp.
		For VSA attributes this call will build the timestamp
		from 4 bytes of data contained after vendorId field.
		If RFC 2865 guidelines conformant VSA value is to be retrieved
		use rather #AsVsaTimestamp()#.

		@return
		PTime representing attribute Value. This timestamp
		is interpreted as number of seconds passed since
	*/
	time_t AsTime() const { return (time_t)AsVsaInteger(); }

	/** Get RFC 2865 guidelines conformant VSA Value as a 32 bit timestamp.
		This call will build the timestamp from 4 bytes of data contained
		after vendorId, vendorType and vendorLength fields.

		@return
		PTime representing attribute Value. This timestamp
		is interpreted as number of seconds passed since
	*/
	time_t AsVsaTime() const { return (time_t)AsVsaInteger(); }

	/** Get attribute Value as IPv4 or IPv6 address.
		For VSA attributes this call will build the IPv4 or IPv6 address
		from 4 / 16 bytes of data contained after vendorId field.
		If RFC 2865 guidelines conformant VSA value is to be retrieved
		use rather #AsVsaAddress()#.

		@return
		IP address representing attribute Value.
	*/
	PIPSocket::Address AsAddress() const;

	/** Get RFC 2865 guidelines conformant VSA Value as IPv4 or IPv6 address.
		This call will build the IP address from 4 or 16 bytes of data contained
		after vendorId, vendorType and vendorLength fields.

		@return
		IP address representing attribute Value.
	*/
	PIPSocket::Address AsVsaAddress() const;

	/** Write this attribute to the buffer. The buffer is resized,
		if necessary, to contain this attribute.

		@return
		True if successfully written (and 'written' receives number
		of bytes written to the buffer).
	*/
	bool Write(
		PBYTEArray & buffer, /// buffer the attribute data will be written to
		PINDEX & written, /// number of bytes written (if successful return)
		PINDEX offset = 0 /// offset into the buffer, where writting starts
		) const;

	/** Assign contents of the attribute 'attr' to this attribute.

		@return
		Reference to this attribute
	*/
	RadiusAttr& operator=(
		const RadiusAttr & attr /// the attribute that contents will be assigned from
		) { memcpy(m_data, attr.m_data, attr.m_length); return *this; }

	/** Check whether this attribute contains valid data.

		@return
		Trye if this attribute is "valid".
	*/
	bool IsValid() const
	{
		return ((PINDEX)m_length) >= ((m_type == VendorSpecific) ? VsaFixedHeaderLength : FixedHeaderLength);
	}

    /** Output PDU to the stream. This is
		primarily used by the standard #operator<<# function.
    */
	void PrintOn(
		ostream & strm /// Stream to print the object into.
		) const;

	friend ostream& operator<<(ostream & s, const RadiusAttr & attr) { attr.PrintOn(s); return s; }

protected:
	/** Read attribute data from the raw buffer.

		@return
		TRUE if attribute has been successfully read.
		Call #GetLength()# to determine how many bytes have been read.
	*/
	bool Read(
		const void* rawData, /// raw buffer with attribute data
		PINDEX rawLength /// length of the buffer
		);

	/** Read attribute data from the byte array.

		@return
		TRUE if attribute has been successfully read.
		Call #GetLength()# to determine how many bytes have been read.
	*/
	bool Read(
		const PBYTEArray & array, /// byte array with the attribute data
		PINDEX offset = 0 /// offset into the buffer, where data starts
		)
	{
		return (array.GetSize() > offset) ? Read(((const BYTE*)array) + offset, array.GetSize() - offset) : false;
	}

protected:
	union {
		/** Attribute raw data. The most important fields:
			data[0] - attribute Type
			data[1] - attribute Length (bytes)
		*/
		unsigned char m_data[MaxLength];
		struct {
			unsigned char m_type;
			unsigned char m_length;
			union {
				unsigned char m_value[MaxLength - FixedHeaderLength];
				struct {
					unsigned char m_vendorId[4];
					unsigned char m_vendorType;
					unsigned char m_vendorLength;
					unsigned char m_vendorValue[MaxLength - VsaRfc2865FixedHeaderLength];
				};
			};
		};
	};
};



/// Encapsulates RADIUS packet (PDU).
class RadiusPDU
{
public:
	/// Useful constants
	enum Constants {
		/// This header is always present
		FixedHeaderLength = 20,
		/// Length of Authenticator vector inside Fixed Header
		AuthenticatorLength = 16,
		/// Offset of Authenticator field from the beginning of PDU data
		AuthenticatorOffset = 4
	};

	/// Standarized RADIUS packet types
	enum Codes {
		Invalid = 0, AccessRequest, AccessAccept, AccessReject,
		AccountingRequest = 4, AccountingResponse, AccountingStatus,
		PasswordRequest = 7,
		PasswordAccept = 8, PasswordReject, AccountingMessage,
		AccessChallenge = 11,
		StatusServer = 12, StatusClient
	};

	/// Minimum and maximum number of bytes per RADIUS packet.
	enum PDUBounds {
		MinPduLength = FixedHeaderLength,
		MaxPduLength = 4096
	};

	/** Create RadiusPDU instance initialized with 0
		or empty values. This object must be initialized
		later with meaningful values.
	*/
	RadiusPDU();

	/// Copy constructor for RADIUS packet.
	RadiusPDU(
		const RadiusPDU & ref /// source RADIUS packet to be copied
		);

	/** Create PDU with no attributes, initializing #code#
		and #id# fields.
	*/
	RadiusPDU(
		unsigned char packetCode, /// code - see #Codes enum#
		unsigned char packetId = 0/// packet id (sequence number)
		);

	/** Create PDU from the raw data buffer. 'rawLength' defines size
		of the buffer. Call #IsValid()# to check if PDU was built successfully
		from the raw data.
	*/
	RadiusPDU(
		const void* rawData, /// raw data buffer
		PINDEX rawLength /// raw data length
		);

	/** Checks whether this PDU contains valid data.

		@return
		TRUE if this PDU is valid.
	*/
	bool IsValid() const;

	/** @return
		Code for this RADIUS packet (see #enum Codes#)
	*/
	unsigned char GetCode() const { return m_code; }

	/** Set new type (Code filed) for this PDU.
	*/
	void SetCode(
		unsigned char newCode /// new PDU type
		) { m_code = newCode; }

	/** @return
		Identifier (Id field) of this RADIUS packet
	*/
	unsigned char GetId() const { return m_id; }

	/**	Set new identifier for this RADIUS packet.
	*/
	void SetId(
		unsigned char newId /// new packet identifier
		) { m_id = newId; }

	/** @return
		Length of this RADIUS packet (bytes)
	*/
	PINDEX GetLength() const { return (((PINDEX)(m_length[0]) & 0xff) << 8) | ((PINDEX)(m_length[1]) & 0xff); }

	/** @return
	    A pointer to a memory block that holds 16 bytes authenticator.
	*/
	const unsigned char* GetAuthenticator() const { return m_authenticator; }

	/** Fill the array with 16 bytes #authenticator# vector
		associated with this RADIUS packet.
	*/
	void GetAuthenticator(
		PBYTEArray & vector, /// buffer where the 16 bytes authenticator will be stored
		PINDEX offset = 0 /// offset into the buffer where the data write starts
		) const;

	/** Fill 16 bytes #authenticator# vector associated with this RADIUS packet
		with data passed in 'vector' parameter.

		@return
		TRUE if authenticator has been set
	*/
	bool SetAuthenticator(
		const PBYTEArray & vector, /// 16 bytes authenticator
		PINDEX offset = 0 /// offset into the buffer where the authenticator starts
		);

	/** Fill 16 bytes #authenticator# vector associated with this RADIUS packet
		with data pointed to by 'data' parameter.

		@return
		TRUE if authenticator has been set
	*/
	bool SetAuthenticator(
		const void* data /// 16 bytes authenticator
		);

	/// Fill #authenticator# vector with 16 bytes of random data.
	void SetAuthenticator(
		PRandom & random /// random generator to be used
		);

	/** Fill Request Authenticator field in this PDU before sending it to
	    RADIUS server. Default implementation sets RA to random vector for
	    non-accounting PDUs, or to MD5 checksum of the whole packet
	    (replacing RA with 0s) + sharedSecret for accounting requests.
	*/
	void SetAuthenticator(
		const PString & secret, /// secret shared between client and server
		PMessageDigest5 & md5 /// MD5 generator
		);

	/** @return
		Number of attributes associated with this RADIUS PDU.
	*/
	PINDEX GetNumAttributes() const;

	/** Appends a clone of this attribute to the attribute list tail.

		@return
		True if the attribute has been appended.
	*/
	bool AppendAttr(
		const RadiusAttr & attr /// attribute to be appended
		);
	RadiusPDU & operator +=(const RadiusAttr & attr)
		{ AppendAttr(attr); return (*this); }

	/// Append a generic attribute
	bool AppendAttr(
		unsigned char attrType, /// Attribute Type
		const void* attrValue, /// buffer with attribute Value data
		PINDEX valueLength /// length of attribute Value data
		);
	/// Append a string attribute
	bool AppendAttr(
		unsigned char attrType, /// Attribute Type
		const PString & stringValue /// string to be stored in the attribute Value data
		);
	/// Append an integer attribute
	bool AppendAttr(
		unsigned char attrType, /// Attribute Type
		int intValue /// 32 bit integer to be stored in the attribute Value
		);
	/// Append an IP address attribute
	bool AppendAttr(
		unsigned char attrType, /// Attribute Type
		const PIPSocket::Address & addressValue /// IP address to be stored in the attribute Value
		);
	/// Append a generic VSA attribute
	bool AppendVsaAttr(
		const void* attrValue, /// buffer with data to be stored in the attribute Value
		PINDEX valueLength, /// data length (bytes)
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
		);
	/// Append a string VSA attribute
	bool AppendVsaAttr(
		const PString & stringValue, /// string to be stored in the attribute Value
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
		);
	/// Append an integer VSA attribute
	bool AppendVsaAttr(
		int intValue, /// 32 bit integer to be stored in the attribute Value
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
		);
	/// Append an IP address VSA attribute
	bool AppendVsaAttr(
		const PIPSocket::Address & addressValue, /// IP address to be stored in the attribute Value
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
		);
	/// Append a string Cisco VSA attribute
	bool AppendCiscoAttr(
		unsigned char vendorType, /// vendor-specific attribute type
		const PString & stringValue, /// string to be stored in the attribute Value
		bool vsaHack = false /// true to not prepend attribute name to its value
		);

	/// Copy contents of the given Radius packet to this packet
	RadiusPDU& operator=(const RadiusPDU & pdu) { CopyContents(pdu); return *this; }

	/** @return
	    A pointer to a Radius attribute next after #previousAttr#
	    or to the first one in the packet. #previousAttr# can be used
	    to iterate over all attributes present in the packet.
	    NULL is returned if there are no more (or no at all) attributes.

	    NOTE: All xxxAttr functions return a temporary pointer that is valid
	    only during this object instance lifetime.
	*/
	const RadiusAttr* GetAttr(const RadiusAttr* previousAttr = NULL) const;

	/** Find an attribute of a given type inside the radius packet. The search
		starts from the list head or after the specified attribute.

	    @return
	    A pointer to the attribute found or NULL if no attribute of this type
	    has been found.
	*/
	const RadiusAttr* FindAttr(
		unsigned char attrType, /// attribute type to be matched
		const RadiusAttr* prevAttr = NULL /// start element for the search operation
		) const;

	/** Find a VSA attribute of a given VendorId and VendorType fields
	    inside the radius packet. The search starts from the list head
	    or after the specified attribute.

	    @return
	    A pointer to the attribute found or NULL if no attribute of this type
	    has been found.
	*/
	const RadiusAttr* FindVsaAttr(
		int vendorId, /// vendor identifier to be matched
		unsigned char vendorType, /// vendor attribute type to be matched
		const RadiusAttr* prevAttr = NULL /// start element for the search operation
		) const;

	/** Write this RADIUS packet data into the buffer.

		@return
		TRUE if packet data has been written
	*/
	bool Write(
		PBYTEArray & buffer, /// buffer where the data will be stored
		PINDEX & written, /// number of bytes written (if successful)
		PINDEX offset = 0 /// offset into the buffer, where the write operation starts
		) const;

	/** Scan list of attributes associated with this PDU and encrypts passwords.
	    This implementation hides password stored in User-Name attributes
	    using method described in RFC 2865.

	    @return
	    False if passwords could not be encrypted for some reason.
	*/
	bool EncryptPasswords(
		const PString & secret, /// secret shared between client and server
		PMessageDigest5 & md5 /// MD5 generator
		);

    /** Output PDU to the stream. This is
		primarily used by the standard #operator<<# function.
    */
	void PrintOn(
		ostream & strm /// Stream to print the object into.
		) const;

	friend ostream & operator<<(ostream & s, const RadiusPDU & pdu) { pdu.PrintOn(s); return s; }

protected:
	/** Build PDU object from the raw data buffer.
		Data previously associated with this object is lost.

		@return
		TRUE if the object has been successfully built (e.g. raw
		buffer contained valid data)
	*/
	bool Read(
		const void* rawData, /// raw buffer with PDU data
		PINDEX rawLength /// length (bytes) of the raw buffer
		);

	/** Build PDU object from the raw data buffer.
		Data previously associated with this object is lost.

		@return
		TRUE if the object has been successfully built (e.g. raw
		buffer contained valid data)
	*/
	bool Read(
		const PBYTEArray & buffer, /// buffer with RADIUS packet data
		PINDEX offset = 0 /// offset into the buffer, where data starts
		);

	/// Copy content of RADIUS packet 'pdu' into this object.
	void CopyContents(
		const RadiusPDU & pdu /// packet to copy data from
		);

private:
	/// Set Radius packet length to the given value
	void SetLength(
		PINDEX newLen /// new packet length in bytes
		)
	{
		m_length[0] = (unsigned char)((newLen >> 8) & 0xff);
		m_length[1] = (unsigned char)(newLen & 0xff);
	}

protected:
	union {
		/// raw RADIUS packet data
		unsigned char m_data[MaxPduLength];
		struct {
			/// RADIUS packet type
			unsigned char m_code;
			/// RADIUS packet id (sequence number)
			unsigned char m_id;
			/// RADIUS packet length (big endian)
			unsigned char m_length[2];
			/// RADIUS authenticator vector
			unsigned char m_authenticator[AuthenticatorLength];
			unsigned char m_attributes[MaxPduLength - FixedHeaderLength];
		};
	};
};

/** RADIUS client socket maintaining IDs
	for pending requests and handling requests
	from multiple threads.

	Call #GenerateNewId()# to create new identifier
	that can be used with next RADIUS packet sent
	using this socket. If #GenerateNewId()# returns
	P_MAX_INDEX it means that all IDs are being used
	and you can either: 1. wait for oldest Id to return
	to the pool of free IDs, 2. create new RadiusSocket.
*/
class RadiusSocket : public PUDPSocket
{
	PCLASSINFO(RadiusSocket, PUDPSocket)
public:
	/** Create new socket at given port. Autoselect local network interface.
		Call #IsOpen()# to check if the socket has been created.
	*/
	RadiusSocket(
		/// port number to send requests from (0=autoselect)
		WORD port = 0
		);

	/** Create new socket at given port, bound to the selected
		network interface. Call #IsOpen()# to check if the socket
		has been created.
	*/
	RadiusSocket(
		/// local network interface address
		const PIPSocket::Address & addr,
		/// port number to send requests from
		WORD port = 0
		);

	virtual ~RadiusSocket();

	virtual void PrintOn(ostream & strm) const;

	/** Process RADIUS request/response sequence. It sends Radius packet
		to host 'serverAddress:remotePort' and reads the response into 'pdu'.
		Use #SetReadTimeout()# to set timeout for this operation.

		@return
		True if the RADIUS response has been successfully received
		and stored in a variable referenced by the 'pdu' param.
	*/
	virtual bool MakeRequest(
		const RadiusPDU* request, /// buffer with RADIUS packet to send
		const Address & serverAddress, /// RADIUS server address
		WORD remotePort, /// RADIUS server port
		RadiusPDU * & pdu /// receives RADIUS Response PDU on success
		);

	/** Send RADIUS request and return immediately. It sends the #request#
		to the host 'serverAddress:remotePort' and does not wait for a response.

		@return
		True if the request has been successfully sent.
	*/
	virtual bool SendRequest(
		const RadiusPDU* request, /// buffer with RADIUS packet to send
		const Address & serverAddress, /// RADIUS server address
		WORD remotePort /// RADIUS server port
		);

	/** Generate an unique ID suitable for RadiusPDU identifiers.
		This function automatically calls #RefreshIdCache()#.

		@return
		An identifier in range 0-255 or P_MAX_INDEX if no unique
		ID can be generated at this moment.
	*/
	PINDEX GenerateNewId();

	/** Free any RADIUS packet identifiers, that can be reused
		at this moment.
	*/
	void RefreshIdCache(
		const time_t now = time(NULL) /// current time
		);

	/** @return
		The time interval for generated Identifier to be unique.
	*/
	PTimeInterval GetIdCacheTimeout() const { return m_idCacheTimeout; }

	/** Set new time interval for generated Identifiers to be unique.
		Each generated Identifier can be reused only if the specified
		time interval elapses.
	*/
	void SetIdCacheTimeout(
		const PTimeInterval & timeout /// new timeout
		) { m_idCacheTimeout = timeout; }

	/** @return
		TRUE if the socket is not used by any request any more.
		Be aware, that the socket (port number) cannot be reused
		until all its allocated IDs are timed out.
	*/
	bool CanDestroy() const { return (m_oldestId == m_nextId); }

	/** @return
		Timestamp of the most recent request issued.
	*/
	PTime GetRecentRequestTime() const { return m_recentRequestTime; }

private:
	PINDEX AllocReadSyncPoint();

	void FreeReadSyncPoint(PINDEX syncPointIndex);

private:
	struct RadiusRequest
	{
		RadiusRequest(
			const RadiusPDU* request,
			RadiusPDU * & response,
			const Address* address,
			WORD port
			) : m_request(request), m_response(response),
				m_addr(address), m_port(port) {}

		const RadiusPDU* m_request;
		RadiusPDU * & m_response;
		const Address* m_addr;
		WORD m_port;
	};

	/** Table filled with requests being currently services
		by this socket. Indexed by request Id.
	*/
	RadiusRequest* m_pendingRequests[256];

	/** SyncPoint for socket read operations. SyncPoints
		are allocated/freed on demand.
	*/
	PSyncPoint* m_readSyncPoints[256];
	/** Index for matching request Id with index into
		#readSyncPoints# array.
	*/
	PINDEX m_readSyncPointIndices[256];
	///	Bit map of sync points being used by pending requests
	/// (256 bits)
	DWORD m_syncPointMap[8];
	/// Number of preallocated SyncPoints (for performance reasons)
	/// These SyncPoints get freed on socket destruction
	PINDEX m_permanentSyncPoints;
	/// mutex for mt synchronization
	PTimedMutex m_readMutex;
	/// mutex for atomic WriteTo operation on the socket
	PMutex m_writeMutex;
	/// flag signaling that some request thread performs read operation
	bool m_isReading;
	/// number of pending requests
	PINDEX m_nestedCount;
	/// oldest Id that should not be used (is still valid)
	unsigned char m_oldestId;
	/// next free Id
	unsigned char m_nextId;
	/// timestamps for generated IDs, used to check when
	///	Id can be returned to pool of free IDs
	time_t m_idTimestamps[256];
	/// timestamp of the most recent request performed on this socket
	PTime m_recentRequestTime;
	/// time interval over that generated IDs must be unique
	PTimeInterval m_idCacheTimeout;
	/// save listen address for port notifications
	Address m_addr;
	WORD m_port;
};

class RadiusClient
{
public:
	/** Default UDP ports for RADIUS authorization
		and accounting servers.
	*/
	enum RadiusClientPorts {
		DefaultAuthPort = 1812,
		DefaultAcctPort = 1813,
		Rfc2138AuthPort = 1645, /// obsolete
		Rfc2138AcctPort = 1646  /// obsolete
	};

	/// Some defaults
	enum DefaultValues {
		/// timeout for packet IDs returned back to the pool of available IDs
		DefaultIdCacheTimeout = 9000,
		/// timeout for single request operation
		DefaultRequestTimeout = 2000,
		/// how many times request is send (1==no retransmission)
		DefaultRetries = 2,
		/// timeout for unused sockets to be deleted
		DefaultSocketDeleteTimeout = 60000
	};

	/** Construct a RADIUS protocol client, building a list of RADIUS servers
	    from the string. Custom port number for each RADIUS
		server can be specified by appending ":auth_port:acct_port" string
		to the server name. For example, "radius1.mycompany.com:1812:1813".
		Sample lists may look as follows:
			"192.168.1.1"
			"192.168.1.1:1645:1646"
			"192.168.1.1:1645:1646;192.168.2.1:1812:1813"
			"radius1.gnugk.org"
			"radius1.gnugk.org:1812:1813"
			"radius1.gnugk.org;radius2.gnugk.org"
			"radius1.gnugk.org:1812:1813;radius2.gnugk.org:1645:1646"
	*/
	RadiusClient(
		/// primary RADIUS server
		const PString & servers,
		/// local address for RADIUS client
		const PString & address = PString::Empty(),
		/// default secret shared between the client and the server
		const PString & sharedSecret = PString::Empty()
		);

	/** Construct a RADIUS protocol client reading its settings
	    from the config.
	*/
	RadiusClient(
		PConfig & config, /// config that contains RADIUS settings
		const PString & sectionName /// config section with the settings
		);

	/// Destroy this object
	virtual ~RadiusClient();

	/** @return
		The local IP address this RADIUS client is bound to.
	*/
	PIPSocket::Address GetLocalAddress() const { return m_localAddress; }

	/** Set new time interval for RADIUS packet Identifiers
		to be unique.
		Warning: settings this value to
		short interval can cause packets to be ignored
		by the server, too long value can produce large
		number of client UDP sockets opened at once.

		@return
		True if the new interval has been set.
	*/
	bool SetIdCacheTimeout(
		const PTimeInterval & timeout /// new time interval
		);

	/** Send requestPDU to RADIUS server and waits for response.
		If the response is received, it is returned in responsePDU.

		@return
		True if request/response sequence completed successfully.
	*/
	virtual bool MakeRequest(
		const RadiusPDU & requestPDU, /// PDU with request packet
		RadiusPDU * & responsePDU /// filled with PDU received from RADIUS server
		);

	/** Sends a RADIUS request and does not wait for a response.
		This can be used to send accounting updates, for example.

		@return
		True if the RADIUS request has been successfully sent
		(this does not mean it has arrived at the radius server).
	*/
	virtual bool SendRequest(
		const RadiusPDU & requestPDU /// PDU with request packet
		);

	static WORD GetDefaultAuthPort() { return DefaultAuthPort; }
	static WORD GetDefaultAcctPort() { return DefaultAcctPort; }

protected:
	/** Determine if the #pdu# should be send to auth port
		of RADIUS server (FALSE) or acct port (TRUE).

		@return
		True to send the PDU to the accounting RADIUS server module,
		false to send the PDU to authenticating RADIUS server module.
	*/
	virtual bool IsAcctPDU(
		const RadiusPDU & pdu /// PDU to be checked
		) const;

	/** Retrieves reference to RADIUS socket and RADIUS packet
		identified, that are suitable for a single request.
		That means that for each request, GetSocket call should
		be made to obtain the socket and the id.

		@return:
		True if socket and if are filled with valid data
	*/
	bool GetSocket(
		/// pointer that will be filled with RadiusSocket pointer
		/// on success
		RadiusSocket * & socket,
		/// identifier that will be initialized to valid Id on success
		unsigned char & id
		);

	/** Create new instance of RadiusSocket based class. Can be
		overridden to provide custom RadiusSocket implementations.

		@return
		Pointer to the new socket
	*/
	virtual RadiusSocket* CreateSocket(const PIPSocket::Address & addr, WORD port = 0);

	/** Create new instance of RadiusSocket based class. Can be
		overridden to provide custom RadiusSocket implementations.

		@return
		Pointer to the new socket
	*/
	virtual RadiusSocket* CreateSocket(WORD port = 0);

	/** Verify Response Authenticator vector from received PDU.
	    Provided here mainly for RadiusSocket.

	    @return
	    True if RA is valid, FALSE otherwise
	*/
	virtual bool VerifyResponseAuthenticator(
	    const RadiusPDU* request, /// buffer with RADIUS request PDU
	    const RadiusPDU* response, /// buffer with RADIUS response PDU
		const PString & secret /// shared secret used to create the request PDU
	    );

	/// Parse #servers# string and build a list of RADIUS servers from it.
	void GetServersFromString(const PString & servers);

protected:
	typedef std::list<RadiusSocket*>::iterator socket_iterator;
	typedef std::list<RadiusSocket*>::const_iterator socket_const_iterator;

	/// An entry describing a single radius server
	struct RadiusServer
	{
		PString m_serverAddress; /// IP or DNS name
		PString m_sharedSecret; /// password shared between the client and the server
		WORD m_authPort; /// port number to send Access Requests to
		WORD m_acctPort; /// port number to send Accounting Requests to
	};

	/// NOTE: m_radiusServers and m_sharedSecret are expected to be constant
	///       during the object lifetime
	/// list of RADIUS servers
	std::vector<const RadiusServer*> m_radiusServers;
	/// shared password for authorizing this client with RADIUS servers
	PString m_sharedSecret;
	/// default port for RADIUS authentication (if not overridden)
	WORD m_authPort;
	/// default port for RADIUS accounting (if not overridden)
	WORD m_acctPort;
	/// base UDP port for RADIUS client
	WORD m_portBase;
	/// upper UDP port limit for RADIUS client
	WORD m_portMax;
	/// timeout value for processing RADIUS client requests
	PTimeInterval m_requestTimeout;
	/// time interval over which the packet Id has to be unique (for a single client port)
	PTimeInterval m_idCacheTimeout;
	/// timeout for unused sockets to be deleted from the pool
	PTimeInterval m_socketDeleteTimeout;
	/// number of packet retransmissions to a single RADIUS server
	unsigned m_numRetries;
	/// how RADIUS packers are retransmitted
	/// 0: numRetries to server #1, numRetries to server #2, ...
	/// 1: 1st packet to #1, 1st packet to #2, ..., 2nd packet to #1, ...
	bool m_roundRobinServers;
	/// local address that the client should bind to when making requests
	PIPSocket::Address m_localAddress;
	/// array of active RADIUS client sockets
	std::list<RadiusSocket*> m_activeSockets;
	/// mutex for accessing #activeSockets# and other stuff
	mutable PMutex m_socketMutex;
};

#endif /* __RADPROTO_H */

#endif /* HAS_RADIUS */
