/*
 * radproto.h
 *
 * RADIUS protocol client classes that offer good performance,
 * scalability and multithreading access. 
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.5  2003/09/24 00:22:03  zvision
 * Removed time_t RadAttr constructors
 *
 * Revision 1.4  2003/09/12 16:31:16  zvision
 * Accounting initially added to the 2.2 branch
 *
 * Revision 1.3  2003/08/20 14:46:19  zvision
 * Avoid PString reference copying. Small code improvements.
 *
 * Revision 1.2  2003/08/19 10:44:19  zvision
 * Initially added to 2.2 branch
 *
 * Revision 1.1.2.5  2003/07/03 15:32:20  zvision
 * Fixed comments. Removed md5 param from VerifyResponseAuthenticator.
 *
 * Revision 1.1.2.4  2003/06/19 10:52:24  zvision
 * Added AcctStatusTypes enum.
 *
 * Revision 1.1.2.3  2003/06/05 10:02:21  zvision
 * Bugfixes and small code cleanup.
 *
 * Revision 1.1.2.2  2003/05/13 17:45:01  zvision
 * Added attribute searching functions
 *
 * Revision 1.1.2.1  2003/04/23 20:14:56  zvision
 * Initial revision
 *
 */
#ifndef __RADPROTO_H
#define __RADPROTO_H "@(#) $Id$"

#include <ptlib/sockets.h>
#include <ptclib/cypher.h>
#include <ptclib/random.h>

/** Encapsulates RADIUS Attribute structure.
*/
class RadiusAttr : public PObject
{
	PCLASSINFO(RadiusAttr,PObject)
public:
	/// Type for List of RADIUS attributes
	PLIST(List,RadiusAttr);

	enum Constants
	{
		/// max length of the attribute raw data
		MaxLength = 255, 
		/// length of the attribute fixed header (Type+Length)
		FixedHeaderLength = 2, 
		/// max length of the Value field
		MaxValueLength = (MaxLength-FixedHeaderLength), 
		/// length of the fixed header for VSA
		/// (standard header + VendorId field)
		VsaFixedHeaderLength = FixedHeaderLength+4, 
		/// max length of the VSA Value field
		VsaMaxValueLength = (MaxLength-VsaFixedHeaderLength),
		/// length of the fixed header for RFC2865 conformant VSA
		/// (standard header + VendorId, VendorType and VendorLength fields)
		VsaRfc2865FixedHeaderLength = VsaFixedHeaderLength+2,
		/// max length of the VSA RFC2865 conformant Value field
		VsaMaxRfc2865ValueLength = (MaxLength-VsaRfc2865FixedHeaderLength) 
	};

	/// Constants for RADIUS Attribute Type field
	enum AttrTypes
	{
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
		AcctInterimInterval = 85, AcctTunnelPacketsLost, NasPortId
	};

	/// Constants for Service-Type attribute values
	enum ServiceTypes
	{
		ST_Login = 1, ST_Framed, ST_CallbackLogin, 
		ST_CallbackFramed = 4, ST_Outbound, ST_Administrative, 
		ST_NasPrompt = 7,
		ST_AuthenticateOnly = 8, ST_CallbackNasPrompt, ST_CallCheck, 
		ST_CallbackAdministrative = 9
	};

	/// Constants for Framed-Protocol attribute values
	enum FramedProtocols
	{
		FP_Ppp = 1,
		FP_Slip
	};

	/// Constants for Framed-Compression attribute values
	enum FramedCompressionTypes
	{
		FC_None = 0,
		FC_VJTcpIp,
		FC_Ipx,
		FC_StacLZS
	};

	/// Constants for Login-Service attribute values
	enum LoginServiceTypes
	{
		LS_Telnet = 0, LS_Rlogin, LS_TcpClear, LS_PortMaster,
		LS_Lat, LS_X25_PAD, LS_X25_T3POS, LS_TcpClearQuiet
	};

	/// Constants for NAS-Port-Type attribute values
	enum NASPortTypes
	{
		NasPort_Asynchronous = 0, NasPort_Synchronous, NasPort_IsdnSynchronous,
		NasPort_IsdnAsynchronousV120 = 3, NasPort_IsdnAsynchronousV110,
		NasPort_Virtual = 5, NasPort_Piafs, NasPort_HdlcClearChannel,
		NasPort_X25 = 8, NasPort_X75, NasPort_G3Fax, NasPort_SDSL,
		NasPort_AdslCap = 12, NasPort_AdslDmt, NasPort_Idsl, NasPort_Ehternet,
		NasPort_xDsl = 16, NasPort_Cable, NasPort_WirelessOther, 
		NasPort_WirelessIeee8021 = 19
	};

	/// Constants for Acct-Status-Type atribute values
	enum AcctStatusTypes
	{
		AcctStatus_Start = 1,
		AcctStatus_Stop = 2,
		AcctStatus_InterimUpdate = 3,
		AcctStatus_AccountingOn = 7,
		AcctStatus_AccountingOff = 8
	};
	
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
		const RadiusAttr& attr /// atrribute to copy from
		);
		
	/** Create TLV RADIUS attribute of a given type,
		initializing #value# field with 'stringValue.GetLength()' bytes
		from 'stringValue' string. In case of VSA,
		#vsaVendorId# is extracted from data contained in the #value# field.
	*/
	RadiusAttr( 
		unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
		const PString& stringValue /// string to be stored in the attribute Value data
		);

	/** Create TLV RADIUS attribute of a given type,
		initializing #value# field with an integer value passed
		with 'intValue' parameter. This constructor should be also used
		for attributes carrying 32 bit timestamps.
	*/
	RadiusAttr( 
		unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
		int intValue /// 32 bit integer to be stored in the attribute Value
		);

	/** Create TLV RADIUS attribute of a given type,
		initializing #value# field with 32 bit IPv4 address
		value passed with 'addressValue' parameter.
	*/
	RadiusAttr( 
		unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
		const PIPSocket::Address& addressValue /// IPv4 address to be stored in the attribute Value
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
		const PString& stringValue, /// string to be stored in the attribute Value
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
		const PIPSocket::Address& addressValue, /// IPv4 address to be stored in the attribute Value
		int vendorId, /// 32 bit vendor identifier
		unsigned char vendorType /// vendor-specific attribute type
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

	/// Destroy the object
	virtual ~RadiusAttr();

	/** @return
		Type of this attribute (see #enum AttrTypes#).
	*/
	unsigned char GetType() const { return data[0]; }

	/** @return
		Vendor-specific type for this attribute, assuming this
		attribute is a VSA that conforms to RFC 2865 guidelines for VSAs
		(has vendorId, vendorType and vendorLength fields).
	*/
	unsigned char GetVsaType() const;

	/** @return
		Total length (bytes) of this attribute.
	*/
	PINDEX GetLength() const { return (PINDEX)(data[1]) & 0xff; }
	
	/** @return
		Length of the Value field for this attribute.
	*/
	PINDEX GetValueLength() const 
	{ 
		const PINDEX len = (PINDEX)(data[1]) & 0xff;
		const PINDEX headerLen 
			= IsVsa() ? VsaFixedHeaderLength : FixedHeaderLength;
		
		return (len<=headerLen) ? 0 : (len-headerLen);
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
	BOOL GetValue( 
		PBYTEArray& val, /// array where data is to be stored
		PINDEX offset = 0 /// offset into the array, where the data write starts
		) const;

	/** Fill the byte array with Value associated with this attribute,
		assuming that this attribute is RFC 2865 guidelines conformant VSA.
		The array is resized, if necessary, to contain the value.
		Call #GetVsaValueLength()# to determine number of bytes written
		to the array
	*/
	BOOL GetVsaValue( 
		PBYTEArray& val, /// array where data is to be stored
		PINDEX offset = 0 /// offset into the array, where the data write starts
		) const;

	/** @return
		TRUE if this is a vendor-specific attribute (VSA).
	*/
	BOOL IsVsa() const { return (data[0] == VendorSpecific); }

	/** @return
		32 bit vendor identifier for VSA. This call is valid only
		for VSA attributes (see #IsVSA()#). Also ensure that this attribute
		is valid (#IsValid()).
	*/
	int GetVsaVendorId() const 
	{
		return (((DWORD)(data[FixedHeaderLength+0]) & 0xff) << 24)
			| (((DWORD)(data[FixedHeaderLength+1]) & 0xff) << 16)
			| (((DWORD)(data[FixedHeaderLength+2]) & 0xff) << 8)
			| ((DWORD)(data[FixedHeaderLength+3]) & 0xff);
	}

	/** Get attribute Value as a string. Be aware that the string
		may contain embedded 0s. For VSA attributes this call will
		build the string from data contained after vendorId field.
		If RFC 2865 guidelines conformant VSA value is to be retrieved
		use rather #AsVsaString()#.
		
		@return
		PString containing attribute Value.
		If an error occurs an empty string is returned.
	*/
	virtual PString AsString() const;

	/** Get RFC 2865 guidelines conformant VSA Value as a string. 
		Be aware that the string may contain embedded 0s. This call will
		build the string from data contained after vendorId, vendorType and
		vendorLength fields.
		
		@return
		PString containing attribute Value.
		If an error occurs an empty string is returned.
	*/
	virtual PString AsVsaString() const;

	/** Get attribute Value as a 32 bit integer. 
		For VSA attributes this call will build the integer 
		from 4 bytes of data contained after vendorId field.
		If RFC 2865 guidelines conformant VSA value is to be retrieved
		use rather #AsVsaInteger()#.
		
		@return
		An integer representing attribute Value.
		If an error occurs 0 is returned.
	*/
	virtual int AsInteger() const;

	/** Get RFC 2865 guidelines conformant VSA Value as a 32 bit integer. 
		This call will build the integer from 4 bytes of data contained 
		after vendorId, vendorType and vendorLength fields.
		
		@return
		An integer representing attribute Value. 
		If an error occurs 0 is returned.
	*/
	virtual int AsVsaInteger() const;

	/** Get attribute Value as a 32 bit timestamp. 
		For VSA attributes this call will build the timestamp
		from 4 bytes of data contained after vendorId field.
		If RFC 2865 guidelines conformant VSA value is to be retrieved
		use rather #AsVsaTimestamp()#.
		
		@return
		PTime representing attribute Value. This timestamp
		is interpreted as number of seconds passed since
	*/
	time_t AsTime() const { return AsVsaInteger(); }

	/** Get RFC 2865 guidelines conformant VSA Value as a 32 bit timestamp. 
		This call will build the timestamp from 4 bytes of data contained 
		after vendorId, vendorType and vendorLength fields.
		
		@return
		PTime representing attribute Value. This timestamp
		is interpreted as number of seconds passed since
	*/
	time_t AsVsaTime() const { return AsVsaInteger(); }

	/** Get attribute Value as a 32 bit IPv4 address. 
		For VSA attributes this call will build the IPv4 address
		from 4 bytes of data contained after vendorId field.
		If RFC 2865 guidelines conformant VSA value is to be retrieved
		use rather #AsVsaAddress()#.
		
		@return
		IPv4 address representing attribute Value.
	*/
	virtual PIPSocket::Address AsAddress() const;

	/** Get RFC 2865 guidelines conformant VSA Value as a 32 bit IPv4 address. 
		This call will build the IPv4 address from 4 bytes of data contained 
		after vendorId, vendorType and vendorLength fields.
		
		@return
		IPv4 address representing attribute Value.
	*/
	virtual PIPSocket::Address AsVsaAddress() const;

	/** Check if two attributes (this one and the 'attr')
		are identical (e.g. have the same type, length, value etc.).

		@return
		TRUE if both attributes have the same contents (are "equal")
	*/
	virtual Comparison SameContents( const RadiusAttr& attr ) const;

	/** Write this attribute to the buffer. The buffer is resized,
		if necessary, to contain this attribute.
		
		@return
		TRUE if successfully written (and 'written' receives number
		of bytes written to the buffer).
	*/
	virtual BOOL Write( 
		PBYTEArray& buffer, /// buffer the attribute data will be written to
		PINDEX& written, /// number of bytes written (if successful return)
		PINDEX offset = 0 /// offset into the buffer, where writting starts
		) const;

	/** Assign contents of the attribute 'attr' to this attribute.
		
		@return
		Reference to this attribute
	*/
	RadiusAttr& operator=( 
		const RadiusAttr& attr /// the attribute that contents will be assigned from
		)
	{
		CopyContents( attr );
		return *this;
	}

    /** Output this attribute to the stream. This is
		primarily used by the standard #operator<<# function.
    */
    virtual void PrintOn(
		ostream &strm   /// Stream to print the object into.
    ) const;
	
	/** Check whether this attribute contains valid data.
	
		@return
		TRUE if this attribute is "valid".
	*/
	virtual BOOL IsValid() const;

    /** Compares two attributes. Equality for two attributes is defined
		as equality of their attribute types (e.g. only Type fields values
		are compared). For VSAs VendorId and VendorType fields are also
		compared. This definition make list searchs easy.
       
		@return
		#LessThan#, #EqualTo# or #GreaterThan#
		according to the relative rank of the attribute Type value.
    */
    virtual Comparison Compare(
		const PObject & obj   // Object to compare against.
		) const;

	/** Create copy of this attribute
		
		@return
		An exact copy of this attribute.
	*/
	virtual PObject* Clone() const;
	
protected:
	/** Construct uninitialized attribute. It should be initialized
		later by other means (operator=, etc.)
	*/
	RadiusAttr();

	/** Copies contents of the attribute 'attr' to this attribute.
	*/
	virtual void CopyContents( 
		const RadiusAttr& attr /// the attribute that contents will be assigned from
		)
	{
		memcpy(&data,&(attr.data),sizeof(data));
	}
		
	/** Read attribute data from the raw buffer.
		
		@return
		TRUE if attribute has been sucessfully read. 
		Call #GetLength()# to determine how many bytes have been read.
	*/
	virtual BOOL Read( 
		const void* rawData, /// raw buffer with attribute data
		PINDEX rawLength /// length of the buffer
		);

	/** Read attribute data from the byte array.
		
		@return
		TRUE if attribute has been sucessfully read.
		Call #GetLength()# to determine how many bytes have been read.
	*/
	BOOL Read( 
		const PBYTEArray& array, /// byte array with the attribute data
		PINDEX offset = 0 /// offset into the buffer, where data starts
		)
	{
		return (array.GetSize() > offset)
			? Read( ((const BYTE*)array) + offset, array.GetSize() - offset )
			: FALSE;
	}

protected:
	/** Attribute raw data. Thr most important fields:
		data[0] - attribute Type
		data[1] - attribute Length (bytes)
	*/
	char data[MaxLength]; 
};



/** Encapsulates RADIUS packet (PDU).
*/
class RadiusPDU : public PObject
{
	PCLASSINFO(RadiusPDU,PObject)
public:
	/// Useful constants
	enum Constants
	{
		/// This header is always present
		FixedHeaderLength = 20,
		/// Length of Authenticator vector inside Fixed Header
		AuthenticatorLength = 16,
		/// Offset of Authenticator field from the beginning of PDU data
		AuthenticatorOffset = 4
	};

	/// Standarized RADIUS packet types
	enum Codes
	{
		Invalid = 0, AccessRequest, AccessAccept, AccessReject,
		AccountingRequest = 4, AccountingResponse, AccountingStatus,
		PasswordRequest = 7,
		PasswordAccept = 8, PasswordReject, AccountingMessage,
		AccessChallenge = 11,
		StatusServer = 12, StatusClient
	};

	/// Minimum and maximum number of bytes per RADIUS packet.
	enum PDUBounds
	{
		MinPduLength = FixedHeaderLength,
		MaxPduLength = 4096
	};

	/** Create RadiusPDU instance initialized with 0 
		or empty values. This object must be intialized 
		later with meaningful values.
	*/
	RadiusPDU();

	/** Copy constructor for RADIUS packet.
	*/
	RadiusPDU( 
		const RadiusPDU& ref /// source RADIUS packet to be copied
		);

	/** Create PDU with no attributes, initializing #code#
		and #id# fields.
	*/
	RadiusPDU( 
		unsigned char packetCode, /// code - see #Codes enum#
		unsigned char packetId = 0/// packet id (sequence number)
		);

	/** Create PDU with the given attributes, initializing #code#
		and #id# fields.
	*/
	RadiusPDU( 
		unsigned char packetCode, /// code - see #enum Codes#
		const RadiusAttr::List& attrs, /// attributes
		unsigned char packetId = 0 /// packet id
		);

	/** Create PDU from the raw data buffer. 'rawLength' defines size
		of the buffer. Call #IsValid()# to check if PDU was built successfully
		from the raw data.
	*/
	RadiusPDU(
		const void* rawData, /// raw data buffer
		PINDEX rawLength /// raw data length
		);

	/// Destroy this object
	virtual ~RadiusPDU();

    /** Output PDU to the stream. This is
		primarily used by the standard #operator<<# function.
    */
	virtual void PrintOn( 
		ostream& strm /// Stream to print the object into.
		) const;

	/** Checks whether this PDU contains valid data.
		
		@return
		TRUE if this PDU is valid.
	*/
	virtual BOOL IsValid() const;

	/** @return
		Code for this RADIUS packet (see #enum Codes#)
	*/
	unsigned char GetCode() const { return code; }
	
	/** Set new type (Code filed) for this PDU.
	*/
	void SetCode( 
		unsigned char newCode /// new PDU type
		) 
		{ code = newCode; }
	
	/** @return
		Identifier (Id field) of this RADIUS packet
	*/
	unsigned char GetId() const { return id; }

	/**	Set new identifier for this RADIUS packet.
	*/
	void SetId( 
		unsigned char newId /// new packet identifier
		) 
		{ id = newId; }

	/** @return
		Length of this RADIUS packet (bytes)
	*/
	PINDEX GetLength() const;

	/** Fill the array with 16 bytes #authenticator# vector
		associated with this RADIUS packet.
	*/
	void GetAuthenticator( 
		PBYTEArray& vector, /// buffer where the 16 bytes authenticator will be stored
		PINDEX offset = 0 /// offset into the buffer where the data write starts
		) const;

	/** Fill 16 bytes #authenticator# vector associated with this RADIUS packet
		with data passed in 'vector' parameter.

		@return
		TRUE if authenticator has been set
	*/
	BOOL SetAuthenticator( 
		const PBYTEArray& vector, /// 16 bytes authenticator
		PINDEX offset = 0 /// offset into the buffer where the authenticator starts
		);

	/** Fill 16 bytes #authenticator# vector associated with this RADIUS packet
		with data pointed to by 'data' parameter.

		@return
		TRUE if authenticator has been set
	*/
	BOOL SetAuthenticator( 
		const void* data /// 16 bytes authenticator
		);

	/** Fill #authenticator# vector with 16 bytes of random data.
	*/
	virtual void SetRandomAuthenticator( 
		PRandom& random /// random generator to be used
		);

	/** @return
		reference to the list of attributes associated with this PDU.
		The list can be manipulated and all changes are reflected to this PDU.
	*/
	RadiusAttr::List& GetAttributes() { return attributes; }
	
	/** Appends a clone of this attribute to the #attributes# list.
		
		@return
		TRUE if the attribute has been appended.
	*/
	BOOL AppendAttribute( 
		const RadiusAttr& attr /// attribute to be appended
		) 
	{
		return AppendAttribute( (RadiusAttr*)(attr.Clone()) );
	}
	
	/** Appends this attribute to the #attributes# list. No clone is made.
		
		@return
		TRUE if the attribute has been appended.
	*/
	virtual BOOL AppendAttribute( 
		RadiusAttr* attr 
		);

	virtual BOOL AppendAttributes(
		const RadiusAttr::List& list
		);
		
	RadiusPDU& operator +=( const RadiusAttr& attr )
	{
		AppendAttribute( attr );
		return (*this);
	}

	RadiusPDU& operator +=( RadiusAttr* attr )
	{
		AppendAttribute( attr );
		return (*this);
	}

	RadiusPDU& operator +=( const RadiusAttr::List& list )
	{
		AppendAttributes( list );
		return (*this);
	}
	
	RadiusPDU& operator=( const RadiusPDU& pdu )
	{
		CopyContents( pdu );
		return *this;
	}

	RadiusPDU& operator=( const RadiusAttr::List& list )
	{
		attributes.RemoveAll();
		AppendAttributes( list );
		return *this;
	}

	/** Find attribute of a given type on the list
		of attributes for this RADIUS PDU. The search
		starts from the list head or a specified index.
		
		@return
		An index of the attribute found or P_MAX_INDEX
		if no attribute of this type has been found.
	*/
	PINDEX FindAttribute(
		unsigned char attrType, /// attribute type to be matched
		PINDEX offset = 0 /// start element for the search operation
		) const;
		
	/** Find VSA attribute of given VendorId and VendorType fields
		on the list of attributes for this RADIUS PDU. The search
		starts from the list head or a specified index.
		
		@return
		An index of the attribute found or P_MAX_INDEX
		if no attribute of this type has been found.
	*/
	PINDEX FindAttribute(
		int vendorId, /// vendor identifier to be matched
		unsigned char vendorType, /// vendor attribute type to be matched
		PINDEX offset = 0 /// start element for the search operation
		) const;

	/** Return a pointer to the attribute with the given index
		on the attributes list.
		
		@return
		A pointer to the attribute or NULL if invalid index has been
		specified. Be aware that this pointer should not be stored
		for later use.
	*/
	RadiusAttr* GetAttributeAt(
		PINDEX index /// index of the attribute to be retrieved
		) const;

	/** @return
		Number of attributes associated with this RADIUS PDU.
	*/
	PINDEX GetNumAttributes() const
	{
		return attributes.GetSize();
	}
	
	/** Write this RADIUS packet data into the buffer.

		@return
		TRUE if packet data has been written
	*/
	virtual BOOL Write( 
		PBYTEArray& buffer, /// buffer where the data will be stored
		PINDEX& written, /// number of bytes written (if successful)
		PINDEX offset = 0 /// offset into the buffer, where the write operation starts
		) const;


	virtual PObject* Clone() const;
	
protected:
	/** Build PDU object from the raw data buffer. 
		Data previously associated with this object is lost.

		@return
		TRUE if the object has been successfully built (e.g. raw
		buffer contained valid data)
	*/
	virtual BOOL Read( 
		const void* rawData, /// raw buffer with PDU data
		PINDEX rawLength /// length (bytes) of the raw buffer
		);

	/** Build PDU object from the raw data buffer. 
		Data previously associated with this object is lost.

		@return
		TRUE if the object has been successfully built (e.g. raw
		buffer contained valid data)
	*/
	BOOL Read(
		const PBYTEArray& buffer, /// buffer with RADIUS packet data
		PINDEX offset = 0 /// offset into the buffer, where data starts
		);

	/** Create an instance of #RadiusAttr# derived class 
		from the passed raw data buffer.

		@return
		Pointer to the new instance of the attribute.
	*/
	virtual RadiusAttr* BuildAttribute(
		const void* rawData, /// raw buffer with attribute data
		PINDEX rawLength /// length (bytes) of the raw buffer
		) const
	{
		return new RadiusAttr( rawData, rawLength );
	}

	/** Copy content of RADIUS packet 'pdu' into this object.
	*/
	virtual BOOL CopyContents( 
		const RadiusPDU& pdu /// packet to copy data from
		);

protected:
	/// RADIUS packet type
	unsigned char code;
	/// RADIUS packet id (sequence number)
	unsigned char id;
	/// RADIUS authenticator vector
	unsigned char authenticator[AuthenticatorLength];
	/// list of attributes associated with this RADIUS packet
	RadiusAttr::List attributes;
};

/** RADIUS client socket maintaining IDs 
	for pending requests and handling requests
	from multiple threads.
	
	Call #GenerateNewId()# to create new identifier
	that can be used with next RADIUS packet sent
	using this socket. If #GenerateNewId()# retruns
	P_MAX_INDEX it means that all IDs are being used
	and you can either: 1. wait for oldest Id to return
	to the pool of free IDs, 2. create new RadiusSocket.
*/
class RadiusClient;
class RadiusSocket : public PUDPSocket
{
	PCLASSINFO(RadiusSocket,PUDPSocket)
public:
	PBASEARRAY(Array,RadiusSocket*);

	/** Create new socket at given port.
		Autoselect local network interface.
		Call #IsOpen()# to check if the socket
		has been created.
	*/
	RadiusSocket( 
		/// instance of RadiusClient to generate custom RadiusPDUs
		RadiusClient& client,
		/// port number to send requests from (0=autoselect)
		WORD port = 0
		);

	/** Create new socket at given port, bound to the selected
		network interface.
		Call #IsOpen()# to check if the socket
		has been created.
		If you want the socket to create custom
		RadiusPDU based classes (through overriden
		#RadiusPDU::BuildPDU()#), pass non-null
		'client' parameter.
	*/
	RadiusSocket( 
		/// instance of RadiusClient to generate custom RadiusPDUs
		RadiusClient& client,
		/// local network interface address
		const PIPSocket::Address& addr, 
		/// port number to send requests from
		WORD port = 0
		);

	virtual ~RadiusSocket();

	virtual void PrintOn( ostream& strm ) const;
	
	/** Process RADIUS request/response sequense. It sends
		'length' bytes from 'sendBuffer' to host 'serverAddress:remotePort'
		and reads response into 'pdu'.
		Use #SetReadTimeout()# to set timeout for this operation.
		
		@return
		TRUE if RADIUS response has been successfully received
		and stored in a variable referenced by the 'pdu' param.
	*/
	virtual BOOL MakeRequest( 
		const BYTE* sendBuffer, /// buffer with Request RADIUS packet
		PINDEX length, /// length of the Request packet
		const Address& serverAddress, /// RADIUS server address
		WORD remotePort, /// RADIUS server port
		RadiusPDU*& pdu /// receives RADIUS Response PDU on success
		);

	/** Generate unique Id suitable for RadiusPDU identifiers.
		This function automatically calls #RefreshIdCache()#.
		
		@return
		Identifier in range 0-255 or P_MAX_INDEX if no unique
		Id can be generated at this moment.
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
	PTimeInterval GetIdCacheTimeout() const { return idCacheTimeout; }
	
	/** Set new time interval for generated Identifiers to be unique.
		Each generated Identifier can be reused only if the specified
		time interval elapses.
	*/
	void SetIdCacheTimeout( 
		const PTimeInterval& timeout /// new timeout
		) 
		{ idCacheTimeout = timeout; }

	/** @return
		TRUE if the socket is not used by any request any more.
		Be aware, that the socket (port number) cannot be reused
		until all its allocated IDs are timed out.
	*/
	BOOL CanDestroy() const	{ return (oldestId == nextId); }
	
	/** @return
		Timestamp of the most recent request issued.
	*/
	PTime GetRecentRequestTime() const { return recentRequestTime; }
	
private:
	
	PINDEX AllocReadSyncPoint();
	
	void FreeReadSyncPoint( 
		PINDEX syncPointIndex 
		);

private:
	struct ReadInfo
	{
		RadiusPDU*& pdu;
		const BYTE* requestBuffer;
		PINDEX requestLength;
		const Address* address;
		WORD port;

		ReadInfo( 
			RadiusPDU*& _pdu, 
			const BYTE* req, 
			PINDEX reqLen,
			const Address* _address, 
			WORD _port 
			)
			: 
			pdu( _pdu), requestBuffer( req ), 
			requestLength( reqLen ),
			address( _address ), port( _port )
		{}
	};

	/** Table filled with requests being currently services
		by this socket. Indexed by request Id.
	*/
	ReadInfo* pendingRequests[256];
	
	/** SyncPoint for socket read operations. SyncPoints
		are allocated/freed on demand.
	*/
	PSyncPoint* readSyncPoints[256];
	/** Index for matching request Id with index into
		#readSyncPoints# array.
	*/
	PINDEX readSyncPointIndices[256];
	///	Bit map of sync points being used by pending requests
	/// (256 bits)
	DWORD syncPointMap[8];
	/// Number of preallocated SyncPoints (for performance reasons)
	/// These SyncPoints get freed on socket destruction
	PINDEX permanentSyncPoints;
	
	/// buffer for socket read operations
	PBYTEArray readBuffer;
	/// mutex for mt synchronization
	PMutex readMutex;
	/// flag signalling that some request thread performs read operation
	BOOL isReading;
	/// number of pending requests
	PINDEX nestedCount;
	/// oldest Id that should not be used (is still valid)
	unsigned char oldestId;
	/// next free Id
	unsigned char nextId;
	/// timestamps for generated IDs, used to check when
	///	Id can be retruned to pool of free IDs
	time_t idTimestamps[256];
	/// Timestamp of the most recent request performed on this socket
	PTime recentRequestTime;
	/// time interval over that generated IDs must be unique
	PTimeInterval idCacheTimeout;
	/// pointer to RadiusClient object used to generate custom RadiusPDUs
	/// (through #BuildPDU()# virtual methods)
	RadiusClient& radiusClient;
};

class RadiusClient : public PObject
{
	PCLASSINFO(RadiusClient,PObject)
public:
	/** Default UDP ports for RADIUS authorization 
		and accounting servers.
	*/
	enum RadiusClientPorts
	{
		DefaultAuthPort = 1812,
		DefaultAcctPort = 1813,
		Rfc2138AuthPort = 1645, /// obsolete
		Rfc2138AcctPort = 1646  /// obsolete
	};

	/// Some defaults
	enum DefaultValues
	{
		/// timeout for packet IDs returned back to the pool of available IDs
		DefaultIdCacheTimeout = 9000,
		/// timeout for single request operation
		DefaultRequestTimeout = 2000,
		/// how many times request is send (1==no retransmission)
		DefaultRetries = 2,
		/// timeout for unused sockets to be deleted
		DefaultSocketDeleteTimeout = 60000
	};

	/// Request Authenticator generation method for outgoing PDUs
	enum RAGenerator
	{
		/// RA intialized with random 16 bytes vector
		RAGeneratorRandom = 0,
		/// RA initialized with MD5(code+length+16 zeros+attributes+sharedSecret)
		RAGeneratorMD5 = 1
	};
	
	/** Construct a RADIUS protocol client with RADIUS servers
		set as parameters specify. Custom port number for each RADIUS
		server can be specified by appending ":auth_port:acct_port" string 
		to the server name. For example, "radius1.mycompany.com:1812:1813".
	*/
	RadiusClient( 
		/// primary RADIUS server
		const PString& primaryServer, 
		/// secondary RADIUS server
		const PString& secondaryServer = PString(),
		/// local address for RADIUS client
		const PString& address = PString()
		);
	
	/// Destroy this object
	virtual ~RadiusClient();

	/** Set shared secret to be used to authorize this client
		with RADIUS server.
	*/
	virtual void SetSharedSecret( 
		const PString& secret /// a secret shared between RADIUS client and server
		) 
	{ 
		PWaitAndSignal lock( socketMutex );
		sharedSecret = (const char*)secret; 
	}

	/** Get secret password shared between RADIUS server 
		and the client.

		@return
		Shared secret for communication with RADIUS server
	*/
	PString GetSharedSecret() const 
	{ 
		PWaitAndSignal lock( socketMutex );
		return sharedSecret; 
	}

	/** Get default port number that will be used 
		during communication with radius server (if server name string does
		not specify custom port number).
		
		@return
		port number
	*/
	WORD GetAuthPort() const { return authPort; }

	/** Get default port number that will be used 
		during communication with radius server (if server name string does
		not specify custom port number).
		
		@return
		port number
	*/
	WORD GetAcctPort() const { return acctPort; }

	/** Set default port number that will be used 
		during communication with radius server (if server name string does
		not specify custom port number).
	*/
	void SetAuthPort( WORD port )
	{
		authPort = port;
	}

	/** Set default port number that will be used 
		during communication with radius server (if server name string does
		not specify custom port number).
	*/
	void SetAcctPort( WORD port )
	{
		acctPort = port;
	}

	/** Set UDP port range to be used by the client.
		The effective range will be <base;base+range).

		@return
		TRUE if the new port range has been set.
	*/
	BOOL SetClientPortRange( 
		WORD base, /// base port number
		WORD range /// number of ports in the range 
		);

	/** Append new RADIUS server to the list of servers.
		If the server already exists, no action is performed.
		
		@return
		TRUE if server was successfully added (or already existed) to the list.
	*/
	virtual BOOL AppendServer( 
		const PString& serverName /// new RADIUS server name
		);
		
	/** Get time interval for RADIUS packet Identifiers
		to be unique.

		@return
		Id uniquess time interval.
	*/
	PTimeInterval GetIdCacheInterval() const
	{
		return idCacheTimeout;
	}

	/** Set new time interval for RADIUS packet Identifiers
		to be unique.
		Warning: settings this value to	
		short interval can cause packets to be ignored 
		by the server, too long value can produce large
		number of client UDP sockets opened at once.	

		@return
		TRUE if the new interval has been set.
	*/	
	BOOL SetIdCacheTimeout( 
		const PTimeInterval& timeout /// new time interval
		);

	/** Set timeout values for RADIUS protocol request/response sequence
		to complete. If the timeout elapses and RADIUS server did not respond,
		then this client switches to the next server on the list.
		
		@return
		TRUE if timeout has been set
	*/
	BOOL SetRequestTimeout( 
		const PTimeInterval& timeout /// timeout for RADIUS request/response operation
		);

	/** Get timeout for RADIUS request operation.
		
		@return
		Request timeout
	*/
	PTimeInterval GetRequestTimeout() const { return requestTimeout; }

	/** Set timeout for unused RADIUS client sockets to be deleted.
	*/
	void SetSocketDeleteTimeout(
		const PTimeInterval& timeout /// new timeout
		);

	/** Get timout for unused RADIUS client sockets to be deleted.
	
		@return
		Time period after which unused RADIUS sockets are deleted.
	*/
	PTimeInterval GetSocketDeleteTimeout() const { return socketDeleteTimeout; }
	
	/** Set retry count (retransmission count) for a single RADIUS server.
		The number includes first request (e.g. settings this value to 1
		disables retransmissions).

		@return
		TRUE if the retry count has been changed.
	*/
	BOOL SetRetryCount(
		PINDEX retries /// retry count (must be at least 1)
		);

	/** Get retry count (retransmission count) for a single RADIUS server.
		
		@return
		Max number of retransmission for a single RADIUS server.
	*/
	PINDEX GetRetryCount() const { return numRetries; }

	/** Set retransmission method. 
		Round robin means:
			repeat
				transmit to server #1
				transmit to server #2
				...
				transmit to server #n
			until numRetries
			
		No round robin (default) means:
			repeat
				transmit to server #1
			until numRetries
			repeat
				transmit to server #2
			until numRetries
			...
	*/
	void SetRoundRobinServers(
		BOOL roundRobin /// TRUE for rr behaviour
		)
	{
		roundRobinServers = roundRobin; 
	}
	
	/** Get retransmission method.
		
		@return
		TRUE if round robin method is in use.
	*/
	BOOL GetRoundRobinServers() const { return roundRobinServers; }
			
	/** Send requestPDU to RADIUS server and waits for response.
		If the response is received, it is returned in responsePDU.
	
		@return
		TRUE if request/response sequence completed successfully.
	*/
	virtual BOOL MakeRequest( 
		const RadiusPDU& requestPDU, /// PDU with request packet
		RadiusPDU*& responsePDU /// filled with PDU received from RADIUS server
		);

	/** Build RadiusPDU-derived object from the raw data buffer.
		Override this method to instantiate custom RadiusPDU-derived classes.
	
		@return
		Pointer to the new objet
	*/
	virtual RadiusPDU* BuildPDU( 
		const void* rawData, /// raw data buffer
		PINDEX rawLength /// length of the raw data buffer
		) const
	{
		return new RadiusPDU( rawData, rawLength );
	}

	/** Create RadiusPDU-derived class instance. Can be overriden
		(along with #BuildPDU(const void*,PINDEX)#) to support creation
		custom PDU classes.
		
		@return
		RadiusPDU based class instance
	*/
	virtual RadiusPDU* BuildPDU() const
	{
		return new RadiusPDU();
	}

	/** Verify Response Authenticator vector
	    from received PDU. Provided here mainly
	    for RadiusSocket.
	    
	    @return
	    TRUE if RA is valid, FALSE otherwise
	*/
	virtual BOOL VerifyResponseAuthenticator( 
	    const BYTE* requestBuffer, /// buffer with RADIUS request PDU
	    PINDEX requestLength, /// length of the request PDU
	    const BYTE* responseBuffer, /// buffer with RADIUS response PDU
	    PINDEX responseLength /// length of the response PDU
	    );
	    
	static WORD GetDefaultAuthPort();
	static WORD GetDefaultAcctPort();

protected:
	/** Callback called before request PDU is sent to RADIUS server.
	    It gives the possibility to do something with the PDU.
		The callback is supplied with information, whether the packet
		is retransmitted - and can trigger some attributes update
		(mainly accounting packets).
	    Last line of overriden #OnSendPDU()# should look like:
		
		  changed = changed || overrideChanged
		  
		where overrideChanged is set to TRUE if the implementation
		changed any of the attributes. This ugly hack is given here
		to provide proper way of change propagation flag 
		through derived classes. 
		
	    @return
	    TRUE if proceed with this request
	*/
	virtual BOOL OnSendPDU( 
		/// PDU that is to be sent
		RadiusPDU& pdu, 
		/// TRUE if this is PDU retransmission
		BOOL retransmision, 
		/// set on exit to signal, whether the PDU has been
		/// changed (TRUE) and new packet Id and authenticator
		/// should be generated, or remains unchaned (FALSE)
		BOOL& changed 
		);

	/** Fill Request Authenticator field in the passed RADIUS PDU
		before sending it to RADIUS server. Default implementation
		sets RA to random vector for non-accounting PDUs (e.g. those
		that #IsAcctPDU()# returns FALSE), or to MD5 checksum 
		of the whole packet (replacing RA with 0s) + sharedSecret 
		for accounting requests.
	*/
	virtual void FillRequestAuthenticator( 
		RadiusPDU& pdu,  /// PDU with RA to be filled
		const PString& secret, /// secret shared between client and server
		PMessageDigest5& md5 /// MD5 generator 
		) const;
		
	/** Scan list of attributes associated with the passed PDU
		and encrypts passwords. Default implementation hides
		password stored in User-Name attributes using method
		described in RFC 2865.
	*/
	virtual void EncryptPasswords( 
		RadiusPDU& pdu, /// PDU that will be scaned for password attributes
		const PString& secret, /// secret shared between client and server
		PMessageDigest5& md5 /// MD5 generator
		) const;
	
	/** Callback called after response PDU had been received from RADIUS server
		and before it is returned to the calling application.
		It gives the possibility to do something with the PDU.
	
		@return
		TRUE if proceed with this response
	*/
	virtual BOOL OnReceivedPDU( 
		RadiusPDU& pdu /// PDU that was received
		);

	/** Determine if the #pdu# should be send to auth port
		of RADIUS server (FALSE) or acct port (TRUE).

		@return
		TRUE to send the PDU to the accounting RADIUS server module, 
		FALSE to send the PDU to authenticating RADIUS server module.
	*/
	virtual BOOL IsAcctPDU( 
		const RadiusPDU& pdu /// PDU to be checked
		) const;

	/** Get the method of generating Request Authenticator
		for the passed #pdu#.
		
		@return
		Request Authenticator generator type (see #RAGenerator#)
	*/
	virtual RAGenerator GetRAGenerator( 
		const RadiusPDU& pdu /// PDU to be checked
		) const;
	
	/** Retrieves reference to RADIUS socket and RADIUS packet
		identified, that are suitable for a single request.
		That means that for each request, GetSocket call should
		be made to obtain the socket and the id.
		
		@return:
		TRUE if socket and if are filled with valid data
	*/
	BOOL GetSocket( 
		/// pointer that will be filled with RadiusSocket pointer
		/// on success
		RadiusSocket*& socket, 
		/// identifier that will be initialized to valid Id on success
		unsigned char& id 
		);

	/** Create new instance of RadiusSocket based class. Can be
		overriden to provide custom RadiusSocket implementations.
		
		@return
		Pointer to the new socket
	*/
	virtual RadiusSocket* CreateSocket( 
		const PIPSocket::Address& addr, 
		WORD port = 0 
		)
	{
		return new RadiusSocket( *this, addr, port );
	}
	
	/** Create new instance of RadiusSocket based class. Can be
		overriden to provide custom RadiusSocket implementations.
		
		@return
		Pointer to the new socket
	*/
	virtual RadiusSocket* CreateSocket( 
		WORD port = 0 
		)
	{
		return new RadiusSocket( *this, port );
	}
	
protected:
	/// list of RADIUS servers
	PStringArray radiusServers;
	/// shared secret password for authorizing this client with RADIUS servers
	PString sharedSecret;
	/// default port for RADIUS authentication (if not overriden)
	WORD authPort;
	/// default port for RADIUS accounting (if not overriden)
	WORD acctPort;
	/// base UDP port for RADIUS client
	WORD portBase;
	/// upper UDP port limit for RADIUS client
	WORD portMax;
	/// timeout value for processing RADIUS client requests
	PTimeInterval requestTimeout;
	/// time interval over which the packet Id has to be unique (for a single client port)
	PTimeInterval idCacheTimeout;
	/// timeout for unused sockets to be deleted from the pool
	PTimeInterval socketDeleteTimeout;
	/// number of packet retransmissions to a single RADIUS server
	int numRetries;
	/// how RADIUS packers are retransmitted
	/// 0: numRetries to server #1, numRetries to server #2, ...
	/// 1: 1st packet to #1, 1st packet to #2, ..., 2nd packet to #1, ...
	BOOL roundRobinServers;
	
	/// local address that the client should bind to when making requests
	PIPSocket::Address localAddress;
	/// array of active RADIUS client sockets
	RadiusSocket::Array activeSockets;
	/// mutex for accessing #activeSockets# and other stuff
	PMutex socketMutex;
};


#endif /* __RADPROTO_H */
