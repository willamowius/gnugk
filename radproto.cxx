/*
 * radproto.cxx
 *
 * RADIUS protocol classes.
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.12  2004/03/17 00:00:38  zvision
 * Conditional compilation to allow to control RADIUS on Windows just by setting HA_RADIUS macro
 *
 * Revision 1.11  2004/03/11 13:42:48  zvision
 * 64-bit fixes from Klaus Kaempf
 *
 * Revision 1.10  2003/11/11 11:14:21  zvision
 * Fixed invalid signed/unsigned integer conversions for radius attributes.
 * Optimized radius attributes handling.
 *
 * Revision 1.9  2003/10/31 00:02:27  zvision
 * A better tracing/error reporting
 *
 * Revision 1.8  2003/10/21 10:47:16  zvision
 * Fixed minor compilation warnings about precision loss
 *
 * Revision 1.7  2003/10/08 12:40:48  zvision
 * Realtime accounting updates added
 *
 * Revision 1.6  2003/09/28 15:47:23  zvision
 * Better RADIUS client socket handling
 *
 * Revision 1.5  2003/09/24 00:22:03  zvision
 * Removed time_t RadAttr constructors
 *
 * Revision 1.4  2003/09/12 16:31:16  zvision
 * Accounting initially added to the 2.2 branch
 *
 * Revision 1.3  2003/08/20 14:46:19  zvision
 * Avoid PString reference copying. Small code improvements.
 *
 * Revision 1.2  2003/08/19 10:44:18  zvision
 * Initially added to 2.2 branch
 *
 * Revision 1.1.2.8  2003/07/20 23:18:51  zvision
 * Fixed trace output.
 *
 * Revision 1.1.2.7  2003/07/03 15:33:35  zvision
 * Fixed big-endian issues. Fixed small timeout bugs.
 * Fixed strange bug with segfaults on some machines.
 *
 * Revision 1.1.2.6  2003/06/11 12:16:01  zvision
 * Memory usage optimizations.
 * Fixed problems with PSocket::Net2Host call crashing on Solaris.
 *
 * Revision 1.1.2.5  2003/06/05 10:02:20  zvision
 * Bugfixes and small code cleanup.
 *
 * Revision 1.1.2.4  2003/05/26 20:31:09  zvision
 * Better local interface handling in RadiusClient constructor
 *
 * Revision 1.1.2.3  2003/05/13 17:44:40  zvision
 * Added attribute searching functions
 *
 * Revision 1.1.2.2  2003/04/24 11:26:41  willamowius
 * compile fixes for VC 6
 *
 * Revision 1.1.2.1  2003/04/23 20:14:16  zvision
 * Initial revision
 *
 */
#if HAS_RADIUS

#include <ptlib.h>
#include "radproto.h"

#if PTRACING
/// Human-readable attribute names
static const char* radiusAttributeNames[] =
{
/*  0*/	"Invalid", "User-Name", "User-Password", "CHAP-Password",
/*  4*/	"NAS-IP-Address", "NAS-Port", "Service-Type", "Framed-Protocol",
/*  8*/	"Framed-IP-Address", "Framed-IP-Netmask", "Framed-Routing", "Filter-Id",
/* 12*/	"Framed-MTU", "Framed-Compression", "Login-IP-Host", "Login-Service",
/* 16*/	"Login-TCP-Port", "Unknown", "Reply-Message", "Callback-Number",
/* 20*/	"Callback-Id", "Unknown", "Framed-Route", "Framed-IPX-Network",
/* 24*/	"State", "Class", "Vendor-Specific", "Session-Timeout",
/* 28*/	"Idle-Timeout", "Termination-Action", "Called-Station-Id", "Calling-Station-Id",
/* 32*/	"NAS-Identifier", "Proxy-State", "Login-LAT-Service", "Login-LAT-Node",
/* 36*/	"Login-LAT-Group", "Framed-AppleTalk-Link", "Framed-AppleTalk-Network", "Framed-AppleTalk-Zone",
/* 40*/	"Acct-Status-Type", "Acct-Delay-Time", "Acct-Input-Octets", "Acct-Output-Octets",
/* 44*/	"Acct-Session-Id", "Acct-Authentic", "Acct-Session-Time", "Acct-Input-Packets",
/* 48*/	"Acct-Output-Packets", "Acct-Terminate-Cause", "Acct-Multi-Session-Id", "Acct-Link-Count",
/* 52*/	"Acct-Input-Gigawords", "Acct-Output-Gigawords", "Unknown", "Unknown",
/* 56*/	"Unknown", "Unknown", "Unknown", "Unknown",
/* 60*/	"CHAP-Challenge", "NAS-Port-Type", "Port-Limit", "Login-LAT-Port",
/* 64*/	"Unknown", "Unknown", "Unknown", "Unknown",
/* 68*/	"Unknown", "Unknown", "ARAP-Password", "ARAP-Features",
/* 72*/	"ARAP-Zone-Access", "ARAP-Security", "ARAP-Security-Data", "Password-Retry",
/* 76*/	"Prompt", "Connect-Info", "Configuration-Token", "EAP-Message",
/* 80*/	"Message-Authenticator", "Unknown", "Unknown", "Unknown",
/* 84*/	"ARAP-Challenge-Response", "Acct-Interim-Interval", "Unknown", "NAS-Port-Id",
/* 88*/	"Framed-Pool",
/* 89*/	"Unknown"
};

/// Human readable RADIUS packet code names
static const char* radiusPacketCodeNames[] =
{
/* 0*/ "Invalid", "Access-Request", "Access-Accept", "Access-Reject",
/* 4*/ "Accounting-Request", "Accounting-Response", "Unknown", "Unknown",
/* 8*/ "Unknown", "Unknown", "Access-Challenge", "Status-Server",
/*12*/ "Status-Client", "Unknown"
};

/** Macro that returns name associated with the given attribute type.
	Returns "Unknown" if the name is not defined.
*/
#define PMAP_ATTR_TYPE_TO_NAME(type) \
	(((unsigned)(type) >= sizeof(radiusAttributeNames)/sizeof(radiusAttributeNames[0])) \
		? radiusAttributeNames[sizeof(radiusAttributeNames)/sizeof(radiusAttributeNames[0])-1] \
		: radiusAttributeNames[(unsigned)type])

/** Macro that returns name associated with the given RADIUS packet code.
	Returns "Unknown" if the name is not defined.
*/
#define PMAP_CODE_TO_NAME(code) \
	(((unsigned)(code) >= sizeof(radiusPacketCodeNames)/sizeof(radiusPacketCodeNames[0])) \
		? radiusPacketCodeNames[sizeof(radiusPacketCodeNames)/sizeof(radiusPacketCodeNames[0])-1] \
		: radiusPacketCodeNames[(unsigned)code])

#endif /* #if PTRACING */


RadiusAttr::RadiusAttr()
{
	// do not zero whole attribute contents due to performance reasons
	data[0] = data[1] = 0;
}

RadiusAttr::RadiusAttr(
	const RadiusAttr& attr
	)
{
	memcpy(data,attr.data,attr.data[1]);
}

RadiusAttr::RadiusAttr( 
	unsigned char attrType, /// type of the attribute
	const void* attrValue, /// actual attribute value data
	PINDEX valueLength /// length for the attribute value
	)
{
	data[0] = attrType;
	data[1] = FixedHeaderLength;

	if( valueLength > 0 )
		PAssertNULL(attrValue);

#ifdef _DEBUG
	PAssert(valueLength<=MaxValueLength,PInvalidParameter);
#endif

	if( valueLength > MaxValueLength )
		valueLength = MaxValueLength;

	if( valueLength > 0 ) {
		data[1] += valueLength;
		if( attrValue != NULL )
			memcpy(data+FixedHeaderLength,attrValue,valueLength);
	}
}

RadiusAttr::RadiusAttr(
	const void* attrValue, /// buffer with data to be stored in the attribute Value
	PINDEX valueLength, /// data length (bytes)
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	)
{
	data[0] = VendorSpecific;
	data[1] = VsaRfc2865FixedHeaderLength;
	
	data[FixedHeaderLength+0] = (BYTE)((vendorId>>24) & 0xff);
	data[FixedHeaderLength+1] = (BYTE)((vendorId>>16) & 0xff);
	data[FixedHeaderLength+2] = (BYTE)((vendorId>>8) & 0xff);
	data[FixedHeaderLength+3] = (BYTE)(vendorId & 0xff);
	
	data[VsaFixedHeaderLength+0] = vendorType;
	data[VsaFixedHeaderLength+1] = 2;

	if( valueLength > 0 )
		PAssertNULL(attrValue);
	
#ifdef _DEBUG
	PAssert(valueLength<=VsaMaxRfc2865ValueLength,PInvalidParameter);
#endif

	if( valueLength > VsaMaxRfc2865ValueLength )
		valueLength = VsaMaxRfc2865ValueLength;
	
	if( valueLength > 0 ) {
		data[1] += valueLength;
		data[VsaFixedHeaderLength+1] += valueLength;
		if( attrValue != NULL )
			memcpy(data+VsaRfc2865FixedHeaderLength,attrValue,valueLength);
	}
}


RadiusAttr::RadiusAttr( 
	unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
	const PString& stringValue /// string to be stored in the attribute Value data
	)
{
	data[0] = attrType;
	data[1] = FixedHeaderLength;

	if( attrType == VendorSpecific )
		PAssertAlways( PInvalidParameter );

	PINDEX attrLength = stringValue.GetLength();
	
	if( attrLength > MaxValueLength )
		attrLength = MaxValueLength;

	if( attrLength > 0 ) {
		data[1] += attrLength;
		memcpy(data+FixedHeaderLength,(const char*)stringValue,attrLength);
	}
}

RadiusAttr::RadiusAttr( 
	unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
	int intValue /// 32 bit integer to be stored in the attribute Value
	)
{
	data[0] = attrType;
	data[1] = FixedHeaderLength + 4;

	if( attrType == VendorSpecific )
		PAssertAlways( PInvalidParameter );

	data[FixedHeaderLength+0] = (BYTE)((intValue>>24) & 0xff);
	data[FixedHeaderLength+1] = (BYTE)((intValue>>16) & 0xff);
	data[FixedHeaderLength+2] = (BYTE)((intValue>>8) & 0xff);
	data[FixedHeaderLength+3] = (BYTE)(intValue & 0xff);
}

RadiusAttr::RadiusAttr( 
	unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
	const PIPSocket::Address& addressValue /// IPv4 address to be stored in the attribute Value
	)
{
	data[0] = attrType;
	data[1] = FixedHeaderLength + 4;

	if( attrType == VendorSpecific )
		PAssertAlways( PInvalidParameter );

	const DWORD addr = (DWORD)addressValue;
	
	data[FixedHeaderLength+0] = ((const BYTE*)&addr)[0];
	data[FixedHeaderLength+1] = ((const BYTE*)&addr)[1];
	data[FixedHeaderLength+2] = ((const BYTE*)&addr)[2];
	data[FixedHeaderLength+3] = ((const BYTE*)&addr)[3];
}

RadiusAttr::RadiusAttr( 
	const PString& stringValue, /// string to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	)
{
	data[0] = VendorSpecific;
	data[1] = VsaRfc2865FixedHeaderLength;

	data[FixedHeaderLength+0] = (BYTE)((vendorId>>24) & 0xff);
	data[FixedHeaderLength+1] = (BYTE)((vendorId>>16) & 0xff);
	data[FixedHeaderLength+2] = (BYTE)((vendorId>>8) & 0xff);
	data[FixedHeaderLength+3] = (BYTE)(vendorId & 0xff);
	
	data[VsaFixedHeaderLength+0] = vendorType;
	data[VsaFixedHeaderLength+1] = 2;

	PINDEX vsaLength = stringValue.GetLength();

#ifdef _DEBUG	
	PAssert(vsaLength<=VsaMaxRfc2865ValueLength,PInvalidParameter);
#endif
	if( vsaLength > VsaMaxRfc2865ValueLength )
		vsaLength = VsaMaxRfc2865ValueLength;

	if( vsaLength > 0 ) {
		data[1] += vsaLength;
		data[VsaFixedHeaderLength+1] += vsaLength;
		
		memcpy( data+VsaRfc2865FixedHeaderLength,
			(const char*)stringValue, vsaLength
			);
	}
}

RadiusAttr::RadiusAttr( 
	int intValue, /// 32 bit integer to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	)
{
	data[0] = VendorSpecific;
	data[1] = VsaRfc2865FixedHeaderLength + 4;

	data[FixedHeaderLength+0] = (BYTE)((vendorId>>24) & 0xff);
	data[FixedHeaderLength+1] = (BYTE)((vendorId>>16) & 0xff);
	data[FixedHeaderLength+2] = (BYTE)((vendorId>>8) & 0xff);
	data[FixedHeaderLength+3] = (BYTE)(vendorId & 0xff);
	
	data[VsaFixedHeaderLength+0] = vendorType;
	data[VsaFixedHeaderLength+1] = 2 + 4;

	data[VsaRfc2865FixedHeaderLength+0] = (BYTE)((intValue>>24) & 0xff);
	data[VsaRfc2865FixedHeaderLength+1] = (BYTE)((intValue>>16) & 0xff);
	data[VsaRfc2865FixedHeaderLength+2] = (BYTE)((intValue>>8) & 0xff);
	data[VsaRfc2865FixedHeaderLength+3] = (BYTE)(intValue & 0xff);
}

RadiusAttr::RadiusAttr( 
	const PIPSocket::Address& addressValue, /// IPv4 address to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	)
{
	data[0] = VendorSpecific;
	data[1] = VsaRfc2865FixedHeaderLength + 4;

	data[FixedHeaderLength+0] = (BYTE)((vendorId>>24) & 0xff);
	data[FixedHeaderLength+1] = (BYTE)((vendorId>>16) & 0xff);
	data[FixedHeaderLength+2] = (BYTE)((vendorId>>8) & 0xff);
	data[FixedHeaderLength+3] = (BYTE)(vendorId & 0xff);
	
	data[VsaFixedHeaderLength+0] = vendorType;
	data[VsaFixedHeaderLength+1] = 2 + 4;

	const DWORD addr = (DWORD)addressValue;
	
	data[VsaRfc2865FixedHeaderLength+0] = ((BYTE*)&addr)[0];
	data[VsaRfc2865FixedHeaderLength+1] = ((BYTE*)&addr)[1];
	data[VsaRfc2865FixedHeaderLength+2] = ((BYTE*)&addr)[2];
	data[VsaRfc2865FixedHeaderLength+3] = ((BYTE*)&addr)[3];
}

RadiusAttr::RadiusAttr(
	const void* rawData, /// buffer with the attribute raw data
	PINDEX rawLength /// length (bytes) of the buffer
	)
{
	data[0] = data[1] = 0;
	Read( rawData, rawLength );
}

RadiusAttr::~RadiusAttr()
{
}

BOOL RadiusAttr::Write(
	PBYTEArray& buffer, /// buffer the attribute data will be written to
	PINDEX& written, /// number of bytes written (if successful return)
	PINDEX offset /// offset into the buffer, where writting starts
	) const
{
	if( !IsValid() )
		return FALSE;

	const PINDEX len = data[1];
	memcpy( buffer.GetPointer(offset+len) + offset, data, len );
	written = len;

	return TRUE;
}

BOOL RadiusAttr::Read( const void* rawData, PINDEX rawLength )
{
//	memset(data,0,sizeof(data));
	data[0] = data[1] = 0;

#ifdef _DEBUG	
	PAssertNULL(rawData);
	PAssert(rawLength>=FixedHeaderLength,PInvalidParameter);
#endif

	if( (rawData == NULL) || (rawLength < FixedHeaderLength) )
		return FALSE;

	const PINDEX len = ((const unsigned char*)rawData)[1];
	
	if( (len < FixedHeaderLength) || (len > rawLength)
		|| ( (((const unsigned char*)rawData)[0] == VendorSpecific)
			&& (len < VsaFixedHeaderLength) ) )
		return FALSE;

	memcpy(data,rawData,len);

	return TRUE;
}

void RadiusAttr::PrintOn(
	ostream &strm   /// Stream to print the object into.
    ) const
{
	const int indent = strm.precision() + 2;

	if( !IsValid() ) {
		strm << "(Invalid) {\n";
		if( data[1] > 0 ) {
			const _Ios_Fmtflags flags = strm.flags();
			const PBYTEArray value( (const BYTE*)data, data[1], FALSE );

			strm << hex << setfill('0') << resetiosflags(ios::floatfield)
				<< setprecision(indent) << setw(16);

			if( (value.GetSize() <= 32) || ((flags&ios::floatfield) != ios::fixed) )
				strm << value << '\n';
			else {
				const PBYTEArray truncatedArray( (const BYTE*)value, 32, FALSE );
				strm << truncatedArray << '\n'
					<< setfill(' ')
					<< setw(indent+4) << "...\n";
			}

			strm << dec << setfill(' ');
			strm.flags(flags);
		}
		strm << setw(indent) << "}\n" << setprecision(indent-2);
		return;
	}
	
	strm << "{\n";
		
#if PTRACING
	strm << setw(indent+7) << "type = " << (unsigned)(data[0])
		<< " (" << PMAP_ATTR_TYPE_TO_NAME(data[0]) << ")\n";
#else
	strm << setw(indent+7) << "type = " << (unsigned)(data[0]) << '\n';
#endif
	const PINDEX totalLen = data[1];
	
	strm << setw(indent+9) << "length = " << totalLen << " octets\n";
	
	if( !IsVsa() ) {
		const _Ios_Fmtflags flags = strm.flags();
		const PINDEX valueLen = (totalLen<=FixedHeaderLength) 
			? 0 : (totalLen-FixedHeaderLength);
		const PBYTEArray value( (const BYTE*)(data+FixedHeaderLength), valueLen, FALSE );

		strm << setw(indent+8) << "value = " << value.GetSize() << " octets {\n";
		strm << hex << setfill('0') << resetiosflags(ios::floatfield)
			<< setprecision(indent+2) << setw(16);

		if( value.GetSize() > 0 ) {
			if( (value.GetSize() <= 32) || ((flags&ios::floatfield) != ios::fixed) )
				strm << value << '\n';
			else {
				const PBYTEArray truncatedArray( (const BYTE*)value, 32, FALSE );
				strm << truncatedArray << '\n'
					<< setfill(' ')
					<< setw(indent+6) << "...\n";
			}
		}

		strm << dec << setfill(' ') << setprecision(indent);
		strm.flags(flags);
		strm << setw(indent+2) << "}\n";
	} else {
		strm << setw(indent+11) << "vendorId = " 
			<< GetVsaVendorId() << '\n';

		const _Ios_Fmtflags flags = strm.flags();
		const PINDEX valueLen = (totalLen<=VsaFixedHeaderLength)
			? 0 : (totalLen-VsaFixedHeaderLength);
		const PBYTEArray value( (const BYTE*)(data+VsaFixedHeaderLength), valueLen, FALSE );

		strm << setw(indent+14) << "vendorValue = " << value.GetSize() << " octets {\n";
		strm << hex << setfill('0') << resetiosflags(ios::floatfield)
			<< setprecision(indent+2) << setw(16);

		if( value.GetSize() > 0 ) {
			if( (value.GetSize() <= 32) || ((flags&ios::floatfield) != ios::fixed) )
				strm << value << '\n';
			else {
				const PBYTEArray truncatedArray( (const BYTE*)value, 32, FALSE );
				strm << truncatedArray << '\n'
					<< setfill(' ')
					<< setw(indent+6) << "...\n";
			}
		}

		strm << dec << setfill(' ') << setprecision(indent);
		strm.flags(flags);
		strm << setw(indent+2) << "}\n";
	}
	strm << setw(indent) << "}\n" << setprecision(indent-2);
}

PINDEX RadiusAttr::GetVsaValueLength() const
{
	PINDEX len = data[1];
	len = (len<=VsaRfc2865FixedHeaderLength) 
		? 0 : (len-VsaRfc2865FixedHeaderLength);
	
	PINDEX len2 = 0;
	if( len > 0 ) {
		len2 = data[VsaFixedHeaderLength+1];
		len2 = (len2<=2) ? 0 : (len2-2);
	}
	if( len2 < len )
		len = len2;
		
	return len;
}

BOOL RadiusAttr::GetValue( PBYTEArray& buffer, PINDEX offset ) const
{
	if( !IsValid() )
		return FALSE;
		
	const PINDEX len = GetValueLength();

	if( len > 0 )	
		memcpy( buffer.GetPointer(offset+len)+offset,
			data + (IsVsa()?VsaFixedHeaderLength:FixedHeaderLength), len
			);
		
	return TRUE;
}

BOOL RadiusAttr::GetVsaValue( PBYTEArray& buffer, PINDEX offset ) const
{
	if( !(IsValid() && IsVsa()) )
		return FALSE;
		
	const PINDEX len = GetVsaValueLength();

	if( len > 0 )	
		memcpy( buffer.GetPointer(len+offset)+offset,
			data + VsaRfc2865FixedHeaderLength, len
			);
		
	return TRUE;
}

PString RadiusAttr::AsString() const
{
	if( !IsValid() )
		return PString();

	const PINDEX len = data[1];
	const PINDEX headerLen = (data[0] == VendorSpecific) 
			? VsaFixedHeaderLength : FixedHeaderLength;

	if( len <= headerLen )
		return PString();
	else
		return PString( (const char*)(data+headerLen), len-headerLen );
}

int RadiusAttr::AsInteger() const
{
	if( data[1] < (FixedHeaderLength+4) || data[0] == VendorSpecific )
		return 0;
	
	return (((DWORD)data[FixedHeaderLength+0]) << 24)
		| (((DWORD)data[FixedHeaderLength+1]) << 16)
		| (((DWORD)data[FixedHeaderLength+2]) << 8)
		| ((DWORD)data[FixedHeaderLength+3]);
}

PIPSocket::Address RadiusAttr::AsAddress() const
{
	if( data[1] < (FixedHeaderLength+4) || data[0] == VendorSpecific )
		return 0;

	DWORD addr = 0;
	
	((BYTE*)&addr)[0] = data[FixedHeaderLength+0];
	((BYTE*)&addr)[1] = data[FixedHeaderLength+1];
	((BYTE*)&addr)[2] = data[FixedHeaderLength+2];
	((BYTE*)&addr)[3] = data[FixedHeaderLength+3];
	
	return addr;
}

PString RadiusAttr::AsVsaString() const
{
	if( (!IsValid()) || (data[0] != VendorSpecific) )
		return PString();
		
	const PINDEX len = data[1];

	if( len <= VsaRfc2865FixedHeaderLength )
		return PString();
	else
		return PString( (const char*)(data+VsaRfc2865FixedHeaderLength), 
			len-VsaRfc2865FixedHeaderLength 
			);
}

int RadiusAttr::AsVsaInteger() const
{
	if( data[1] < (VsaRfc2865FixedHeaderLength+4) || data[0] != VendorSpecific )
		return 0;
		
	return (((DWORD)data[VsaRfc2865FixedHeaderLength+0]) << 24)
		| (((DWORD)data[VsaRfc2865FixedHeaderLength+1]) << 16)
		| (((DWORD)data[VsaRfc2865FixedHeaderLength+2]) << 8)
		| ((DWORD)data[VsaRfc2865FixedHeaderLength+3]);
}

PIPSocket::Address RadiusAttr::AsVsaAddress() const
{
	if( data[1] < (VsaRfc2865FixedHeaderLength+4) || data[0] != VendorSpecific )
		return 0;
	
	DWORD addr = 0;
	
	((BYTE*)&addr)[0] = data[VsaRfc2865FixedHeaderLength+0];
	((BYTE*)&addr)[1] = data[VsaRfc2865FixedHeaderLength+1];
	((BYTE*)&addr)[2] = data[VsaRfc2865FixedHeaderLength+2];
	((BYTE*)&addr)[3] = data[VsaRfc2865FixedHeaderLength+3];
	
	return addr;
}

PObject::Comparison RadiusAttr::Compare(
	const PObject & obj   // Object to compare against.
	) const
{
	if( !obj.IsDescendant(RadiusAttr::Class()) ) {
		PAssertAlways(PInvalidCast);
		return GreaterThan;
	}

	if( !(IsValid() && ((const RadiusAttr&)obj).IsValid()) ) {
#ifdef _DEBUG
		PAssertAlways(PInvalidParameter);
#endif
		return GreaterThan;
	}

	const RadiusAttr& attr = (const RadiusAttr&)obj;
	const PINDEX thisType = data[0];
	const PINDEX attrType = attr.data[0];
	
	if( thisType > attrType )
		return GreaterThan;
	else if( thisType < attrType )
		return LessThan;
	else {
		const PINDEX thisLen = data[1];
		const PINDEX attrLen = attr.data[1];
		
		if( (thisType == VendorSpecific) && (thisLen >= VsaFixedHeaderLength) 
			&& (attrLen >= VsaFixedHeaderLength) ) {
			const DWORD thisVendorId = GetVsaVendorId();
			const DWORD objVendorId = attr.GetVsaVendorId();
			
			if( thisVendorId > objVendorId )
				return GreaterThan;
			else if( thisVendorId < objVendorId )
				return LessThan;
			else {
				if( (thisLen >= VsaRfc2865FixedHeaderLength) 
					&& (attrLen >= VsaRfc2865FixedHeaderLength) ) {
					const DWORD thisVsaType = GetVsaType();
					const DWORD objVsaType = attr.GetVsaType();
					
					if( thisVsaType > objVsaType )
						return GreaterThan;
					else if( thisVsaType < objVsaType )
						return LessThan;
				}
			}
		}
	}
	return EqualTo;
}

PObject* RadiusAttr::Clone() const
{
	return new RadiusAttr( *this );
}

PObject::Comparison RadiusAttr::SameContents( const RadiusAttr& attr ) const
{
	const PINDEX thisLen = data[1];
	const PINDEX attrLen = attr.data[1];
	
	if( thisLen < attrLen )
		return LessThan;
	else if( thisLen > attrLen )
		return GreaterThan;
	else {
		if( thisLen == 0 )
			return EqualTo;
		
		const int result = memcmp(data,attr.data,thisLen);

		return (result==0) ? EqualTo : ((result>0) ? GreaterThan : LessThan);
	}
}

void RadiusAttr::CopyContents( 
	const RadiusAttr& attr /// the attribute that contents will be assigned from
	)
{
	memcpy(&data,&(attr.data),attr.data[1]);
}


RadiusPDU::RadiusPDU()
	:
	code( 0 ),
	id( 0 )
{
//	memset(authenticator,0,sizeof(authenticator));
}

RadiusPDU::RadiusPDU( 
	const RadiusPDU& pdu 
	)
	:
	code( pdu.code ),
	id( pdu.id )
{
	memcpy(authenticator,pdu.authenticator,sizeof(authenticator));
	attributes = pdu.attributes;
	attributes.MakeUnique();
}

RadiusPDU::RadiusPDU( 
	unsigned char packetCode, /// code - see #Codes enum#
	unsigned char packetId /// packet id (sequence number)
	)
	:
	code( packetCode ),
	id( packetId )
{
//	memset(authenticator,0,sizeof(authenticator));
}

RadiusPDU::RadiusPDU( 
	unsigned char packetCode, /// code - see #Codes enum#
	const RadiusAttr::List& attrs, /// attributes
	unsigned char packetId /// packet id (sequence number)
	)
	:
	code( packetCode ),
	id( packetId )
{
	attributes = attrs;
	attributes.MakeUnique();
}

RadiusPDU::RadiusPDU(
	const void* rawData, /// raw data buffer
	PINDEX rawLength /// raw data length
	)
	:
	code( 0 ),
	id( 0 )
{
	if( !Read(rawData,rawLength) ) {
		attributes.RemoveAll();
		code = id = 0;
	}
}

RadiusPDU::~RadiusPDU()
{
}

PINDEX RadiusPDU::GetLength() const
{
	PINDEX len = FixedHeaderLength;
	const PINDEX numAttrs = attributes.GetSize();
	
	for( PINDEX i = 0; i < numAttrs; i++ ) {
		const RadiusAttr* const attr = (RadiusAttr*)(attributes.GetAt(i));
		if( attr && attr->IsValid() )
			len += attr->GetLength();
		else
			return 0;
	}		
	
	return len;
}

void RadiusPDU::PrintOn( 
	ostream& strm /// Stream to print the object into.
	) const
{
	const int indent = strm.precision() + 2;

	strm << ((!IsValid())?"(Invalid) {\n":"{\n");
	
#if PTRACING
	strm << setw(indent+7) << "code = " << (unsigned)code
		<< " (" << PMAP_CODE_TO_NAME(code) << ")\n";
#else
	strm << setw(indent+7) << "code = " << (unsigned)code << '\n';
#endif
	strm << setw(indent+5) << "id = " << (unsigned)id << '\n';
	strm << setw(indent+9) << "length = " << GetLength() << " octets\n";

	const _Ios_Fmtflags flags = strm.flags();
	const PBYTEArray value( (const BYTE*)authenticator, AuthenticatorLength, FALSE );

	strm << setw(indent+28) << "authenticator = 16 octets {\n";
	strm << hex << setfill('0') << resetiosflags(ios::floatfield)
		<< setprecision(indent+2) << setw(16);
	strm << value << '\n';
	strm << dec << setfill(' ') << setprecision(indent);
	strm.flags(flags);
	strm << setw(indent+2) << "}\n";

	if( attributes.GetSize() == 0 )
		strm << setw(indent+22) << "attributes = <<null>>\n";
	else {
		strm << setw(indent+13) << "attributes = " << attributes.GetSize() << " elements {\n";

		const int aindent = indent + 2;

		for( PINDEX i = 0; i < attributes.GetSize(); i++ ) {
			const RadiusAttr* const attr = (RadiusAttr*)(attributes.GetAt(i));
			if( attr )
				strm << setw(aindent+1) << "[" << i << "]= " 
					<< setprecision(aindent) << *attr
					<< setprecision(indent);
		}
		strm << setw(aindent) << "}\n";
	}

	strm << setw(indent-1) << "}\n" << setprecision(indent-2);
}

BOOL RadiusPDU::IsValid() const
{
	if( code == Invalid )
		return FALSE;

	PINDEX len = FixedHeaderLength;
	const PINDEX numAttrs = attributes.GetSize();
	
	for( PINDEX i = 0; i < numAttrs; i++ ) {
		const RadiusAttr* const attr = (RadiusAttr*)(attributes.GetAt(i));
		if( !(attr && attr->IsValid()) )
			return FALSE;
		len += attr->GetLength();
	}
	
	if( (len < MinPduLength) || (len > MaxPduLength) )
		return FALSE;

	return TRUE;
}

void RadiusPDU::GetAuthenticator( PBYTEArray& vector, PINDEX offset ) const
{
	memcpy(	vector.GetPointer(offset+AuthenticatorLength)+offset,
		authenticator, AuthenticatorLength
		);
}

BOOL RadiusPDU::SetAuthenticator( const PBYTEArray& vector, PINDEX offset )
{
	PINDEX len = vector.GetSize();
	
	if( offset >= len )
		return FALSE;

	len -= offset;

	if( len > 0 )
		memcpy( authenticator, ((const BYTE*)vector)+offset,
			((len<AuthenticatorLength)?len:AuthenticatorLength)
			);

	return TRUE;
}

BOOL RadiusPDU::SetAuthenticator( const void* data )
{
#ifdef _DEBUG
	PAssertNULL(data);
#endif
	if( data == NULL )
		return FALSE;

	memcpy(authenticator,data,AuthenticatorLength);
	return TRUE;
}

void RadiusPDU::SetRandomAuthenticator( PRandom& random )
{
	DWORD r = (DWORD)random;
	authenticator[0] = ((const BYTE*)&r)[0];
	authenticator[1] = ((const BYTE*)&r)[1];
	authenticator[2] = ((const BYTE*)&r)[2];
	authenticator[3] = ((const BYTE*)&r)[3];
	r = (DWORD)random;
	authenticator[4] = ((const BYTE*)&r)[0];
	authenticator[5] = ((const BYTE*)&r)[1];
	authenticator[6] = ((const BYTE*)&r)[2];
	authenticator[7] = ((const BYTE*)&r)[3];
	r = (DWORD)random;
	authenticator[8] = ((const BYTE*)&r)[0];
	authenticator[9] = ((const BYTE*)&r)[1];
	authenticator[10] = ((const BYTE*)&r)[2];
	authenticator[11] = ((const BYTE*)&r)[3];
	r = (DWORD)random;
	authenticator[12] = ((const BYTE*)&r)[0];
	authenticator[13] = ((const BYTE*)&r)[1];
	authenticator[14] = ((const BYTE*)&r)[2];
	authenticator[15] = ((const BYTE*)&r)[3];
}

BOOL RadiusPDU::AppendAttributes( const RadiusAttr::List& list )
{
	const PINDEX lsize = list.GetSize();
	
	for( PINDEX i = 0; i < lsize; i++ ) {
		const RadiusAttr* const attr = (const RadiusAttr*)(list.GetAt(i));
		if( attr && attr->IsValid() )
			AppendAttr( (RadiusAttr*)(attr->Clone()) );
		else
			return FALSE;
	}
			
	return TRUE;
}

PINDEX RadiusPDU::FindAttr(
	unsigned char attrType, /// attribute type to be matched
	PINDEX offset /// start element for the search operation
	) const
{
	const PINDEX numAttrs = attributes.GetSize();
	for( PINDEX i = offset; i < numAttrs; i++ ) {
		const RadiusAttr* attr = (const RadiusAttr*)(attributes.GetAt(i));
		if( attr && attr->GetType() == attrType )
			return i;
	}
	return P_MAX_INDEX;
}
		
PINDEX RadiusPDU::FindVsaAttr(
	int vendorId, /// vendor identifier to be matched
	unsigned char vendorType, /// vendor attribute type to be matched
	PINDEX offset /// start element for the search operation
	) const
{
	const PINDEX numAttrs = attributes.GetSize();
	for( PINDEX i = offset; i < numAttrs; i++ ) {
		const RadiusAttr* attr = (const RadiusAttr*)(attributes.GetAt(i));
		if( attr && attr->GetType() == RadiusAttr::VendorSpecific 
			&& attr->IsValid() && attr->GetVsaVendorId() == vendorId
			&& attr->GetVsaType() == vendorType )
			return i;
	}
	return P_MAX_INDEX;
}

PObject* RadiusPDU::Clone() const
{
	return new RadiusPDU( *this );
}

BOOL RadiusPDU::Write( PBYTEArray& buffer, PINDEX& written, PINDEX offset ) const
{
	if( !IsValid() )
		return FALSE;

	const PINDEX len = GetLength();

	BYTE* buffptr = buffer.GetPointer(len+offset)+offset;

	*buffptr++ = code;
	*buffptr++ = id;
	*buffptr++ = (BYTE)(((len)>>8) & 0xff);
	*buffptr++ = (BYTE)(len & 0xff);

	memcpy(buffptr,authenticator,AuthenticatorLength);
	buffptr += AuthenticatorLength;

	written = FixedHeaderLength;

	const PINDEX numAttributes = attributes.GetSize();
	
	for( PINDEX i = 0; i < numAttributes; i++ ) {
		PINDEX writtenA = 0;
		if( !attributes[i].Write(buffer,writtenA,written+offset) )
			return FALSE;
		written += writtenA;
	}

	return TRUE;
}

BOOL RadiusPDU::Read( const void* rawData, PINDEX rawLength )
{
#ifdef _DEBUG
	PAssertNULL(rawData);
	PAssert( rawLength >= MinPduLength, PInvalidParameter );
#endif

	code = id = 0;

	if( (rawData == NULL) || (rawLength < MinPduLength) )
		return FALSE;

	const BYTE* buffptr = (const BYTE*)rawData;

	code = *buffptr++;
	id = *buffptr++;

	const PINDEX length = (((PINDEX)(*buffptr) & 0xff) << 8) 
		| ((PINDEX)(*(buffptr+1)) & 0xff);

	buffptr += 2;
	
	if( (length > rawLength) || (length < MinPduLength) ) {
		code = id = 0;
		return FALSE;
	}

	memcpy(authenticator,buffptr,AuthenticatorLength);
	buffptr += AuthenticatorLength;

	attributes.RemoveAll();

	PINDEX currentPosition = FixedHeaderLength;

	while( currentPosition < length ) {
		RadiusAttr* attr = new RadiusAttr( buffptr, length-currentPosition );
		
		if( !(attr && attr->IsValid()) ) {
			code = id = 0;
			attributes.RemoveAll();
			delete attr;
			return FALSE;
		}

		attributes.Append( attr );
		const PINDEX len = attr->GetLength();
		currentPosition += len;
		buffptr += len;
	}
	
	return TRUE;
}

BOOL RadiusPDU::Read(
		const PBYTEArray& buffer, /// buffer with RADIUS packet data
		PINDEX offset /// offset into the buffer, where data starts
		)
{
	const PINDEX len = buffer.GetSize();

	if( len <= offset )
		return FALSE;

	return Read( ((const BYTE*)buffer) + offset, len - offset );
}

BOOL RadiusPDU::CopyContents( const RadiusPDU& pdu )
{
	code = id = 0;

	if( !pdu.IsValid() )
		return FALSE;

	code = pdu.code;
	id = pdu.id;
	memcpy( authenticator, pdu.authenticator, AuthenticatorLength );

	attributes = pdu.attributes;
	attributes.MakeUnique();
	
	return TRUE;
}


#ifndef DEFAULT_PERMANENT_SYNCPOINTS
#define DEFAULT_PERMANENT_SYNCPOINTS 8
#endif

RadiusSocket::RadiusSocket( 
	RadiusClient& client,
	WORD port 
	)
	:
	permanentSyncPoints( DEFAULT_PERMANENT_SYNCPOINTS ),
	readBuffer( RadiusPDU::MaxPduLength ),
	isReading( FALSE ),
	nestedCount( 0 ),
	idCacheTimeout( RadiusClient::DefaultIdCacheTimeout ),
	radiusClient( client )
{
	Listen(0,port);
	
	int i;
	PRandom random;
	const unsigned _id_ = random;
	oldestId = nextId = (BYTE)(_id_^(_id_>>8)^(_id_>>16)^(_id_>>24));

	memset(readSyncPoints,0,sizeof(readSyncPoints));
		
	if( IsOpen() ) {
		memset(pendingRequests,0,sizeof(pendingRequests));
		memset(syncPointMap,0,sizeof(syncPointMap));
		memset(idTimestamps,0,sizeof(idTimestamps));

		for( i = 0; i < 256; i++ )
			readSyncPointIndices[i] = P_MAX_INDEX;

		for( i = 0; i < permanentSyncPoints; i++ )
			readSyncPoints[i] = new PSyncPoint();
	}
}

RadiusSocket::RadiusSocket( 
	RadiusClient& client,
	const PIPSocket::Address& addr, 
	WORD port
	)
	:
	permanentSyncPoints( DEFAULT_PERMANENT_SYNCPOINTS ),
	readBuffer( RadiusPDU::MaxPduLength ),
	isReading( FALSE ),
	nestedCount( 0 ),
	idCacheTimeout( RadiusClient::DefaultIdCacheTimeout ),
	radiusClient( client )
{
	Listen(addr,0,port);
	
	int i;
	PRandom random;
	const unsigned _id_ = random;
	oldestId = nextId = (BYTE)(_id_^(_id_>>8)^(_id_>>16)^(_id_>>24));

	memset(readSyncPoints,0,sizeof(readSyncPoints));

	if( IsOpen() ) {
		memset(pendingRequests,0,sizeof(pendingRequests));
		memset(syncPointMap,0,sizeof(syncPointMap));
		memset(idTimestamps,0,sizeof(idTimestamps));

		for( i = 0; i < 256; i++ )
			readSyncPointIndices[i] = P_MAX_INDEX;

		for( i = 0; i < permanentSyncPoints; i++ )
			readSyncPoints[i] = new PSyncPoint();
	}
}

RadiusSocket::~RadiusSocket()
{
	PWaitAndSignal lock( readMutex );
	
	for( int i = 0; i < 256; i++ )
		delete readSyncPoints[i];
}

void RadiusSocket::PrintOn( ostream& strm ) const
{
	strm<<"port:"<<GetPort()
		<<'['<<nestedCount<<','<<(PINDEX)oldestId<<'-'<<(PINDEX)nextId<<']';
}

PINDEX RadiusSocket::AllocReadSyncPoint()
{
	PINDEX idx = 0;
	
	for( PINDEX k = 0; k < 8; k++ )
		if( syncPointMap[k] != 0xffffffff ) {
			for( PINDEX i = 0, j = 1; i < 32; i++, j <<= 1, idx++ )
				if( (syncPointMap[k] & ((DWORD)j)) == 0 ) {
					syncPointMap[k] |= (DWORD)j;
					if( readSyncPoints[idx] == NULL )
						readSyncPoints[idx] = new PSyncPoint();
					return idx;
				}
		} else
			idx += 32;
			
	return P_MAX_INDEX;
}

void RadiusSocket::FreeReadSyncPoint( PINDEX syncPointIndex )
{
	if( (syncPointIndex < 256) && (syncPointIndex >= 0) ) {
		syncPointMap[(syncPointIndex >> 5) & 7] 
			&= ~(DWORD)(((DWORD)1)<<(syncPointIndex & 31));
		if( syncPointIndex >= permanentSyncPoints ) {
			delete readSyncPoints[syncPointIndex];
			readSyncPoints[syncPointIndex] = NULL;
		}
	}
}

BOOL RadiusSocket::MakeRequest( 
	const BYTE* sendBuffer, 
	PINDEX length, 
	const Address& serverAddress, 
	WORD serverPort,
	RadiusPDU*& pdu
	)
{
	if( !IsOpen() )
		return FALSE;

	if( (sendBuffer==NULL) || (length<RadiusPDU::MinPduLength) )
		return FALSE;
		
	const unsigned char id = sendBuffer[1];
	const PTimeInterval timeout = GetReadTimeout();
	const PTime startTime;
	BOOL shouldRead = FALSE;
	PSyncPoint* syncPoint = NULL;
	RadiusRequest* requestInfo = NULL;

	{
		if( !readMutex.Wait( timeout ) ) {
			PTRACE(4,"RADIUS\tMutex timed out for the request (id:" 
				<<(PINDEX)id<<')'
				);
			return FALSE;
		}

		PWaitAndSignal lock( readMutex, FALSE );

		if( pendingRequests[id] != NULL ) {
			PTRACE(1,"RADIUS\tDuplicate RADIUS socket request (id:" 
				<<(PINDEX)id<<')'
				);
			return FALSE;
		}

		if( !isReading )
			isReading = shouldRead = TRUE;
		else {
			const PINDEX index = AllocReadSyncPoint();
			if( index == P_MAX_INDEX ) {
				PTRACE(1,"RADIUS\tFailed to allocate a new mutex for the request (id:" 
					<<(PINDEX)id<<')'
					);
				return FALSE;
			}
			syncPoint = readSyncPoints[index];
			if( syncPoint == NULL ) {
				PTRACE(1,"RADIUS\tFailed to allocate a new mutex for the request (id:" 
					<<(PINDEX)id<<')'
					);
				FreeReadSyncPoint(index);
				return FALSE;
			}
			readSyncPointIndices[id] = index;
			nestedCount++;
		}
		
		requestInfo = pendingRequests[id] 
			= new RadiusRequest( pdu, sendBuffer, length, 
				&serverAddress, serverPort 
				);
	}

	writeMutex.Wait();
	BOOL result = WriteTo( sendBuffer, length, serverAddress, serverPort );
	if( !result )
		PTRACE(5,"RADIUS\tError sending UDP packet ("
			<<GetErrorCode(LastWriteError)<<':'
			<<GetErrorNumber(LastWriteError)<<':'
			<<GetErrorText(LastWriteError)<<" (id:"<<(PINDEX)id<<')'
			);
	writeMutex.Signal();
	
	if( result )	
	do
	{
		result = FALSE;
		
		if( shouldRead ) {
			PIPSocket::Address remoteAddress;
			WORD remotePort;

			result = ReadFrom( readBuffer.GetPointer(readBuffer.GetSize()), 
				readBuffer.GetSize(), remoteAddress, remotePort 
				);
			if( !result ) {
				if( GetErrorCode(LastReadError) == Timeout )
					PTRACE(6,"RADIUS\tTimed out reading socket "<<*this);
				else
					PTRACE(5,"RADIUS\tError reading socket "<<*this
						<<" ("<<GetErrorCode(LastReadError)<<':'
						<<GetErrorNumber(LastReadError)<<':'
						<<GetErrorText(LastReadError)<<')'
						);
				break;
			}
			
			result = FALSE;
				
			PINDEX bytesRead = GetLastReadCount();

			if( bytesRead < RadiusPDU::MinPduLength ) {
				PTRACE(5,"RADIUS\tReceived packet is too small ("
					<< bytesRead << ')'
					);
				continue;
			}
	
			PINDEX len = (((PINDEX)(((const BYTE*)readBuffer)[2]) & 0xff)<<8)
				| ((PINDEX)(((const BYTE*)readBuffer)[3]) & 0xff);
				
			if( (len < RadiusPDU::MinPduLength) || (len > RadiusPDU::MaxPduLength) ) {
				PTRACE(5,"RADIUS\tReceived packet has invalid size (" 
					<<len<<')' 
					); 
				continue;
			}

			if( len > bytesRead ) {
				PTRACE(5,"RADIUS\tReceived packet is too small (" 
					<<bytesRead<<"), expected "<<len<<" octets"
					);
				continue;
			}
				
			const BYTE newId = ((const BYTE*)readBuffer)[1];
			
			if( !readMutex.Wait( timeout ) ) {
				PTRACE(5,"RADIUS\tTimed out (mutex) - dropping PDU (id:"
					<<(PINDEX)newId
					);
				continue;
			}
				
			PWaitAndSignal lock( readMutex, FALSE );

			if( pendingRequests[newId] == NULL ) {
				PTRACE(5,"RADIUS\tUnmatched PDU received (code:"
					<<(PINDEX)(((const BYTE*)readBuffer)[0])<<",id:"
					<<(PINDEX)newId<<')'
					);
				continue;
			}

			if( (remoteAddress != *(pendingRequests[newId]->address)) 
				|| (remotePort != pendingRequests[newId]->port) ) {
				PTRACE(5,"RADIUS\tReceived PDU from unknown address: "
					<<remoteAddress<<':'<<remotePort
					);
				continue;
			}
			
			if( !radiusClient.VerifyResponseAuthenticator(
					pendingRequests[newId]->requestBuffer,
					pendingRequests[newId]->requestLength,
					(const BYTE*)readBuffer,len
					) ) {
				PTRACE(5,"RADIUS\tPDU (id:"<<(PINDEX)newId<<") received from "
					<<remoteAddress<<':'<<remotePort
					<<" has invalid response authenticator"
					);
				continue;
			}
				
			RadiusPDU* newPdu = radiusClient.BuildPDU( 
				(const BYTE*)readBuffer, len 
				);
				
			if( !(newPdu && newPdu->IsValid()) ) {
				if( newPdu )
					PTRACE(5,"RADIUS\tInvalid PDU received - "<<(*newPdu));
				else
					PTRACE(5,"RADIUS\tNULL PDU received");
				delete newPdu;
				continue;
			}

			pendingRequests[newId]->pdu = newPdu;
			pendingRequests[newId] = NULL;
			newPdu = NULL;
					
			if( newId == id ) {
				isReading = FALSE;

				if( nestedCount )
					for( PINDEX i = 0, j = oldestId; i < 256; i++, j = (++j) & 0xff )
						if( (readSyncPointIndices[j] != P_MAX_INDEX)
							&& (readSyncPoints[readSyncPointIndices[j] & 0xff] != NULL) )
						{
							readSyncPoints[readSyncPointIndices[j] & 0xff]->Signal();
							break;
						}
					
				delete requestInfo;
				return TRUE;
			} else if( (readSyncPointIndices[newId] != P_MAX_INDEX)
				&& (readSyncPoints[readSyncPointIndices[newId]] != NULL ) ) {
				readSyncPoints[readSyncPointIndices[newId]]->Signal();
				continue;
			}
		} else {
			result = (syncPoint != NULL) && syncPoint->Wait( timeout );
			if( !result )
				break;
				
			result = FALSE;
				
			PWaitAndSignal lock( readMutex );

			if( pendingRequests[id] == NULL ) {
				FreeReadSyncPoint(readSyncPointIndices[id]);
				readSyncPointIndices[id] = P_MAX_INDEX;
				if( nestedCount )
					nestedCount--;
				delete requestInfo;
				return TRUE;
			}

			if( !isReading ) {
				isReading = shouldRead = TRUE;
					
				FreeReadSyncPoint(readSyncPointIndices[id]);
				readSyncPointIndices[id] = P_MAX_INDEX;
				syncPoint = NULL;
				if( nestedCount )
					nestedCount--;
				continue;
			}
				
			continue;
		}

		if( !result )
			break;

	} while( PTime() < (startTime+timeout) );


	{
		PWaitAndSignal lock( readMutex );

		pendingRequests[id] = NULL;
		
		if( readSyncPointIndices[id] != P_MAX_INDEX ) {
			FreeReadSyncPoint(readSyncPointIndices[id]);
			readSyncPointIndices[id] = P_MAX_INDEX;
			if( nestedCount )
				nestedCount--;
		}

		if( isReading && shouldRead ) {
			isReading = FALSE;

			if( nestedCount )
				for( PINDEX i = oldestId, j = 0; j < 256; j++, i = (++i) & 0xff )
					if( (readSyncPointIndices[i] != P_MAX_INDEX)
						&& (readSyncPoints[readSyncPointIndices[i] & 0xff] != NULL) )
					{
						readSyncPoints[readSyncPointIndices[i] & 0xff]->Signal();
						break;
					}
		}
	}

	delete requestInfo;
	return result;
}

BOOL RadiusSocket::SendRequest( 
	const BYTE* sendBuffer, 
	PINDEX length, 
	const Address& serverAddress, 
	WORD serverPort
	)
{
	if( !IsOpen() )
		return FALSE;

	if( (sendBuffer==NULL) || (length<RadiusPDU::MinPduLength) )
		return FALSE;
		
	const unsigned char id = sendBuffer[1];

	PWaitAndSignal lock(writeMutex);
	BOOL result = WriteTo( sendBuffer, length, serverAddress, serverPort );
	if( !result )
		PTRACE(5,"RADIUS\tError sending UDP packet ("
			<<GetErrorCode(LastWriteError)<<':'
			<<GetErrorNumber(LastWriteError)<<':'
			<<GetErrorText(LastWriteError)<<" (id:"<<(PINDEX)id<<')'
			);
	
	return result;
}

void RadiusSocket::RefreshIdCache(
	const time_t now
	)
{
	const PINDEX lastId = ((nextId>=oldestId)?nextId:((PINDEX)nextId+256));
	const long timeout = idCacheTimeout.GetSeconds();
	PINDEX i = oldestId;
	
	while( i++ < lastId && (idTimestamps[oldestId] + timeout) < now )
		++oldestId;
}

PINDEX RadiusSocket::GenerateNewId()
{
	const PTime now;
	const time_t nowInSeconds = now.GetTimeInSeconds();
	
	RefreshIdCache(nowInSeconds);
	
	if( ((nextId + 1) & 0xff) == oldestId )
		return P_MAX_INDEX;
	else {
		recentRequestTime = now;
		idTimestamps[nextId] = nowInSeconds;
		return nextId++;
	}
}

RadiusClient::RadiusClient( 
	/// primary RADIUS server
	const PString& primaryServer, 
	/// secondary RADIUS server
	const PString& secondaryServer,
	/// local address for RADIUS client
	const PString& address
	)
	:
	authPort( RadiusClient::GetDefaultAuthPort() ),
	acctPort( RadiusClient::GetDefaultAcctPort() ),
	portBase( 1024 ),
	portMax( 65535 ),
	requestTimeout( DefaultRequestTimeout ),
	idCacheTimeout( DefaultIdCacheTimeout ),
	socketDeleteTimeout( DefaultSocketDeleteTimeout ),
	numRetries( DefaultRetries ),
	roundRobinServers( FALSE ),
	localAddress( INADDR_ANY )
{
	PString server = primaryServer.Trim();
	
	if( !server.IsEmpty() )
		radiusServers += server;
		
	server = secondaryServer.Trim();
	if( !server.IsEmpty() )
		radiusServers += server;

	if( !address.IsEmpty() )
		if( !PIPSocket::IsLocalHost(address) )
			PTRACE(1,"RADIUS\tSpecified local client address "<<address<<" is not bound to any local interface");
		else
			PIPSocket::GetHostAddress( address, localAddress );

#if PTRACING
	if( PTrace::CanTrace(4) ) {
		ostream& s = PTrace::Begin(4,__FILE__,__LINE__);
		const int indent = s.precision() + 2;
		s << "RADIUS\tCreated instance of RADIUS client (local if: "
			<< localAddress << ", default ports: " << authPort << ',' << acctPort
			<< ") for RADIUS servers group:";
		for( int i = 0; i < radiusServers.GetSize(); i++ )
			s<<'\n'<<setw(indent+radiusServers[i].GetLength())<<radiusServers[i];
		PTrace::End(s);
	}
#endif
}

RadiusClient::RadiusClient( 
	PConfig& config, /// config that contains RADIUS settings
	const PString& sectionName /// config section with the settings
	)
	:
	sharedSecret(config.GetString(sectionName, "SharedSecret", "")),
	authPort((WORD)config.GetInteger(sectionName, "DefaultAuthPort", 
		RadiusClient::GetDefaultAuthPort())),
	acctPort((WORD)config.GetInteger(sectionName, "DefaultAcctPort", 
		RadiusClient::GetDefaultAcctPort())),
	portBase(1024),
	portMax(65535),
	requestTimeout(config.GetInteger(sectionName, "RequestTimeout",
		DefaultRequestTimeout)),
	idCacheTimeout(config.GetInteger(sectionName, "IdCacheTimeout",
		DefaultIdCacheTimeout)),
	socketDeleteTimeout(config.GetInteger(sectionName, "SocketDeleteTimeout",
		DefaultSocketDeleteTimeout)),
	numRetries(config.GetInteger(sectionName, "RequestRetransmissions",
		DefaultRetries)),
	roundRobinServers(config.GetBoolean(
		sectionName, "RoundRobinServers", TRUE)),
	localAddress(INADDR_ANY)
{
	radiusServers = config.GetString(sectionName, "Servers", "").Tokenise(";, |\t", FALSE);

	const PString addr = config.GetString(sectionName, "LocalInterface", "");
	
	if (!addr)
		if (!PIPSocket::IsLocalHost(addr))
			PTRACE(2, "RADIUS\tSpecified local client address '" << addr 
				<< "' is not bound to any local interface"
				);
		else
			PIPSocket::GetHostAddress(addr, localAddress);

	// parse port range (if it does exist)
	const PStringArray s
		= config.GetString(sectionName, "RadiusPortRange", "").Tokenise("-");
	if (s.GetSize() >= 2) { 
		unsigned p1 = s[0].AsUnsigned();
		unsigned p2 = s[1].AsUnsigned();
	
		// swap if base is greater than max
		if (p2 < p1) {
			const unsigned temp = p1;
			p1 = p2;
			p2 = temp;
		}
		
		if (p1 > 65535)
			p1 = 65535;
		if (p2 > 65535)
			p2 = 65535;
	
		if (p1 > 0 && p2 > 0) {
			portBase = (WORD)p1;
			portMax = (WORD)p2;
		}
	}

#if PTRACING
	if( PTrace::CanTrace(4) ) {
		ostream& s = PTrace::Begin(4,__FILE__,__LINE__);
		const int indent = s.precision() + 2;
		s << "RADIUS\tCreated instance of RADIUS client (local if: "
			<< localAddress << ", default ports: " << authPort << ',' << acctPort
			<< ") for RADIUS servers group:";
		for( int i = 0; i < radiusServers.GetSize(); i++ )
			s<<'\n'<<setw(indent+radiusServers[i].GetLength())<<radiusServers[i];
		PTrace::End(s);
	}
#endif
}

RadiusClient::~RadiusClient()
{
	for( PINDEX i = 0; i < activeSockets.GetSize(); i++ )
		delete activeSockets.GetAt(i);
}

BOOL RadiusClient::AppendServer( const PString& serverName )
{
	PString s = serverName.Trim();
	
	if( s.IsEmpty() )
		return FALSE;

	PWaitAndSignal lock( socketMutex );
	
	radiusServers += s;
	
	return TRUE;
}

BOOL RadiusClient::SetClientPortRange( 
	WORD base, /// base port number
	WORD range /// number of ports in the range 
	)
{
	if( range < 1 )
		return FALSE;

	PWaitAndSignal lock( socketMutex );
	
	portBase = base;
	portMax = portBase + (((range-1)<(65535-portBase))
		?(range-1):(65535-portBase)
		);

	return TRUE;
}

BOOL RadiusClient::SetIdCacheTimeout( 
	const PTimeInterval& timeout /// new time interval
	)
{
	PWaitAndSignal lock( socketMutex );
	
	if( timeout < PTimeInterval(1000) )
		return FALSE;
		
	idCacheTimeout = timeout;
	for( int i = 0; i < activeSockets.GetSize(); i++ )
		if( activeSockets.GetAt(i) )
			activeSockets.GetAt(i)->SetIdCacheTimeout( timeout );
			
	return TRUE;
}

BOOL RadiusClient::SetRetryCount(
	PINDEX retries /// retry count (must be at least 1)
	)
{
	if( retries < 1 )
		return FALSE;

	numRetries = retries;

	return TRUE;
}

BOOL RadiusClient::SetRequestTimeout(
	const PTimeInterval& timeout
	)
{
	PWaitAndSignal lock( socketMutex );
	
	if( timeout < PTimeInterval(25) )
		return FALSE;
		
	requestTimeout = timeout;
	for( int i = 0; i < activeSockets.GetSize(); i++ ) 
		if( activeSockets.GetAt(i) ) {
			activeSockets.GetAt(i)->SetReadTimeout( timeout );
			activeSockets.GetAt(i)->SetWriteTimeout( timeout );
		}
			
	return TRUE;
}

BOOL RadiusClient::MakeRequest( 
	const RadiusPDU& requestPDU, /// PDU with request packet
	RadiusPDU*& responsePDU /// filled with PDU received from RADIUS server
	)
{
	if( !requestPDU.IsValid() )
		return FALSE;

	PINDEX length = 0;
	BOOL changed = FALSE;
	BOOL retransmission = FALSE;
	RadiusSocket* socket = NULL;
	unsigned char id;
	PString secret;
	PStringArray servers;
	RadiusPDU* clonedRequestPDU = NULL;
	PBYTEArray sendBuffer;
		
	{ 
		PWaitAndSignal lock( socketMutex );
		
		secret = (const char*)sharedSecret;
		servers = radiusServers;
		servers.MakeUnique();
	}

	for( int i = 0; i < (roundRobinServers ? numRetries * servers.GetSize() : servers.GetSize()); i++ )
	{
		const PINDEX serverIndex = i % servers.GetSize();
		const PTime now;

		PStringArray serverComponents = servers[serverIndex].Tokenise( ":" );
		WORD _authPort = 0, _acctPort = 0;
		
		if( serverComponents.GetSize() < 1 ) {
			PTRACE(1,"RADIUS\tEmpty RADIUS server entry no "<<serverIndex);
			return FALSE;
		}
		
		const PString serverName = serverComponents[0].Trim();
		
		if( serverComponents.GetSize() >= 2 )
			_authPort = (WORD)serverComponents[1].AsUnsigned();
		if( serverComponents.GetSize() >= 3 )	
			_acctPort = (WORD)serverComponents[2].AsUnsigned();
			
		if( _authPort == 0 )
			_authPort = authPort;
		if( _acctPort == 0 )
			_acctPort = acctPort;

		PIPSocket::Address serverAddress;
		const WORD serverPort 
			= IsAcctPDU(requestPDU)?_acctPort:_authPort;

		if( (!PIPSocket::GetHostAddress( serverName, serverAddress ))
			|| (!serverAddress.IsValid()) ) {
			PTRACE(5,"RADIUS\tCould not get IPv4 address for RADIUS server host: "
				<< serverName
				);
			continue;
		}

		for( int j = 0; j < (roundRobinServers ? 1 : numRetries); j++ ) {
			changed = FALSE;
			
			RadiusPDU* oldPDU = clonedRequestPDU;
			clonedRequestPDU = (RadiusPDU*)(requestPDU.Clone());
			
			if( !OnSendPDU(*clonedRequestPDU,retransmission,changed) ) {
				delete clonedRequestPDU;
				delete oldPDU;
				return FALSE;					
			}
				
			if( changed || !retransmission ) {
				delete oldPDU;
				
				{ 
					PWaitAndSignal lock( socketMutex );
		
					if( !GetSocket( socket, id ) ) {
						PTRACE(5,"RADIUS\tSocket allocation failed");
						delete clonedRequestPDU;
						return FALSE;
					}
				}

				clonedRequestPDU->SetId( id );

				PMessageDigest5 md5;
	
				FillRequestAuthenticator( *clonedRequestPDU, secret, md5 );

				EncryptPasswords( *clonedRequestPDU, secret, md5 );
	
				length = clonedRequestPDU->GetLength();
				
				sendBuffer.SetSize( length );

				PINDEX written;
				if( !clonedRequestPDU->Write( sendBuffer, written ) ) {
					delete clonedRequestPDU;
					return FALSE;
				}	
	
				if( written != length ) {
					PTRACE(5,"RADIUS\tNumber of bytes written to the request PDU buffer ("
						<< written << ") does not match PDU length (" << length << ')'
						);
					delete clonedRequestPDU;
					return FALSE;
				}
			} else {
				delete clonedRequestPDU;
				clonedRequestPDU = oldPDU;
			}

#if PTRACING
			if( PTrace::CanTrace(3) ) {
				ostream& strm = PTrace::Begin(3,__FILE__,__LINE__);
				strm<<"RADIUS\tSending PDU to RADIUS server "
					<<serverName<<" ("<<serverAddress<<':'<<serverPort<<')'<<" from "
					<<(*socket)<<", PDU: ";
				if( PTrace::CanTrace(5) )
					strm<<*clonedRequestPDU;
				else
					strm<<PMAP_CODE_TO_NAME(clonedRequestPDU->GetCode())<<", id "
						<<(PINDEX)(clonedRequestPDU->GetId());
				PTrace::End(strm);
			}
#endif
			RadiusPDU* response = NULL;
			
			retransmission = TRUE;
			
			if( !socket->MakeRequest( (const BYTE*)sendBuffer, length, 
					serverAddress, serverPort, response ) ) {
				PTRACE(3,"RADIUS\tReceive response from RADIUS server failed (id:"
					<<(PINDEX)(clonedRequestPDU->GetId())<<')'
					);
				continue;
			}

#if PTRACING
			if( PTrace::CanTrace(3) ) {
				ostream& strm = PTrace::Begin(3,__FILE__,__LINE__);
				strm<<"RADIUS\tReceived PDU from RADIUS server "
					<<serverName<<" ("<<serverAddress<<':'<<serverPort<<')'<<" by socket "
					<<(*socket)<<", PDU: ";
				if( PTrace::CanTrace(5) )
					strm<<(*response);
				else
					strm<<PMAP_CODE_TO_NAME(response->GetCode())<<", id "
						<<(PINDEX)(response->GetId());
				PTrace::End(strm);
			}
#endif
			if( !OnReceivedPDU( *response ) ) {
				delete response;
				continue;
			}
			
			responsePDU = response;
			delete clonedRequestPDU;
			
			return TRUE;
		}
	}

	delete clonedRequestPDU;
	return FALSE;
}

BOOL RadiusClient::SendRequest( 
	const RadiusPDU& requestPDU /// PDU with request packet
	)
{
	if( !requestPDU.IsValid() )
		return FALSE;

	PINDEX length = 0;
	RadiusSocket* socket = NULL;
	unsigned char id;
	PString secret;
	RadiusPDU* clonedRequestPDU = NULL;
	PStringArray serverComponents;
	
	{ 
		PWaitAndSignal lock( socketMutex );
		
		secret = (const char*)sharedSecret;
		serverComponents = radiusServers[0].Tokenise(":");
	}

	const PTime now;
	WORD _authPort = 0, _acctPort = 0;
		
	if( serverComponents.GetSize() < 1 ) {
		PTRACE(1,"RADIUS\tEmpty RADIUS server entry 0");
		return FALSE;
	}
		
	const PString serverName = serverComponents[0].Trim();
		
	if( serverComponents.GetSize() >= 2 )
		_authPort = (WORD)serverComponents[1].AsUnsigned();
	if( serverComponents.GetSize() >= 3 )	
		_acctPort = (WORD)serverComponents[2].AsUnsigned();
			
	if( _authPort == 0 )
		_authPort = authPort;
	if( _acctPort == 0 )
		_acctPort = acctPort;

	PIPSocket::Address serverAddress;
	const WORD serverPort = IsAcctPDU(requestPDU)?_acctPort:_authPort;

	if( (!PIPSocket::GetHostAddress( serverName, serverAddress ))
		|| (!serverAddress.IsValid()) ) {
		PTRACE(3,"RADIUS\tCould not get IPv4 address for RADIUS server host: "
			<< serverName
			);
		return FALSE;
	}

	clonedRequestPDU = (RadiusPDU*)(requestPDU.Clone());
	
	BOOL dummy_changed;
	if( !OnSendPDU(*clonedRequestPDU,FALSE,dummy_changed) ) {
		delete clonedRequestPDU;
		return FALSE;					
	}
				
	{ 
		PWaitAndSignal lock( socketMutex );
		
		if( !GetSocket( socket, id ) ) {
			PTRACE(5,"RADIUS\tSocket allocation failed");
			delete clonedRequestPDU;
			return FALSE;
		}
	}

	clonedRequestPDU->SetId( id );

	PMessageDigest5 md5;
	
	FillRequestAuthenticator( *clonedRequestPDU, secret, md5 );

	EncryptPasswords( *clonedRequestPDU, secret, md5 );
	
	length = clonedRequestPDU->GetLength();
				
	PBYTEArray sendBuffer( length );

	PINDEX written;
	if( !clonedRequestPDU->Write( sendBuffer, written ) ) {
		delete clonedRequestPDU;
		return FALSE;
	}	
	
	if( written != length ) {
		PTRACE(5,"RADIUS\tNumber of bytes written to the request PDU buffer ("
			<< written << ") does not match PDU length (" << length << ')'
			);
		delete clonedRequestPDU;
		return FALSE;
	}

#if PTRACING
	if( PTrace::CanTrace(3) ) {
		ostream& strm = PTrace::Begin(3,__FILE__,__LINE__);
		strm<<"RADIUS\tSending PDU to RADIUS server "
			<<serverName<<" ("<<serverAddress<<':'<<serverPort<<')'<<" from "
			<<(*socket)<<", PDU: ";
		if( PTrace::CanTrace(5) )
			strm<<*clonedRequestPDU;
		else
			strm<<PMAP_CODE_TO_NAME(clonedRequestPDU->GetCode())<<", id "
				<<(PINDEX)(clonedRequestPDU->GetId());
		PTrace::End(strm);
	}
#endif

	if( !socket->SendRequest( sendBuffer, length, serverAddress, serverPort ) ) {
		PTRACE(3,"RADIUS\tError sending RADIUS request (id:"<<(PINDEX)id<<')');
		delete clonedRequestPDU;
		return FALSE;
	}

	delete clonedRequestPDU;
	return TRUE;
}

BOOL RadiusClient::VerifyResponseAuthenticator(
	const BYTE* requestBuffer,
	PINDEX /*requestLength*/,
	const BYTE* responseBuffer,
	PINDEX responseLength
	)
{
	if( responseLength < RadiusPDU::FixedHeaderLength )
		return FALSE;
	
	PMessageDigest5 md5;
#if HAS_NEW_MD5
	PMessageDigest::Result digest;
#else
	PMessageDigest5::Code digest;
#endif

	md5.Process( responseBuffer, RadiusPDU::AuthenticatorOffset );
	md5.Process( requestBuffer + RadiusPDU::AuthenticatorOffset,
		RadiusPDU::AuthenticatorLength
		);
	responseLength -= RadiusPDU::FixedHeaderLength;
	if( responseLength > 0 )
		md5.Process( responseBuffer + RadiusPDU::FixedHeaderLength,
			responseLength
			);
	
	{
		PWaitAndSignal lock( socketMutex );
		const PINDEX secretLength = sharedSecret.GetLength();
		if( secretLength > 0 )
			md5.Process( (const char*)sharedSecret, secretLength );
	}

#if HAS_NEW_MD5
	md5.CompleteDigest( digest );

	return (digest.GetSize() == RadiusPDU::AuthenticatorLength)
		&& memcmp( (const BYTE*)digest.GetPointer(), 
			((const BYTE*)responseBuffer) + RadiusPDU::AuthenticatorOffset,
			RadiusPDU::AuthenticatorLength ) == 0;
#else
	md5.Complete( digest );

	return memcmp( (const BYTE*)&digest, 
		((const BYTE*)responseBuffer) + RadiusPDU::AuthenticatorOffset,
		RadiusPDU::AuthenticatorLength ) == 0;
#endif
}

BOOL RadiusClient::OnSendPDU( 
	RadiusPDU& /*pdu*/,
	BOOL /*retransmission*/,
	BOOL& changed
	)
{
	changed = changed || FALSE;
	return TRUE;
}

BOOL RadiusClient::OnReceivedPDU( 
	RadiusPDU& /*pdu*/
	)
{
	return TRUE;
}

BOOL RadiusClient::IsAcctPDU( const RadiusPDU& pdu ) const
{
	const unsigned char c = pdu.GetCode();
	return (c == RadiusPDU::AccountingRequest) 
		|| (c == RadiusPDU::AccountingResponse)
		|| (c == RadiusPDU::AccountingStatus)
		|| (c == RadiusPDU::AccountingMessage);
}

RadiusClient::RAGenerator RadiusClient::GetRAGenerator( 
	const RadiusPDU& pdu 
	) const
{
	const unsigned char c = pdu.GetCode();
	
	if( c == RadiusPDU::AccountingRequest )
		return RAGeneratorMD5;
		
	return RAGeneratorRandom;
}

WORD RadiusClient::GetDefaultAuthPort()
{
	const WORD port = PSocket::GetPortByService( "udp", "radius" );
	return (port==0) ? (WORD)DefaultAuthPort : port;
}

WORD RadiusClient::GetDefaultAcctPort()
{
	const WORD port = PSocket::GetPortByService( "udp", "radacct" );
	return (port==0) ? (WORD)DefaultAcctPort : port;
}

void RadiusClient::FillRequestAuthenticator( 
	RadiusPDU& pdu, 
	const PString& secret,
	PMessageDigest5& md5
	) const
{
	if( GetRAGenerator(pdu) == RAGeneratorMD5 ) {
		const PINDEX pduLength = pdu.GetLength();
		const PINDEX secretLength = secret.GetLength();
		PBYTEArray buffer( pduLength + secretLength );

		PINDEX written;
		if( pdu.Write( buffer, written ) && (written == pduLength) ) {
			memset( buffer.GetPointer(RadiusPDU::FixedHeaderLength)
					+ RadiusPDU::AuthenticatorOffset,
				0, RadiusPDU::AuthenticatorLength
				);

			if( secretLength > 0 )
				memcpy( buffer.GetPointer(written+secretLength)+written,
					(const char*)secret, secretLength
					);

#if HAS_NEW_MD5
			PMessageDigest::Result digest;
			md5.Encode( buffer, digest );
			pdu.SetAuthenticator( digest.GetPointer() );
#else
			PMessageDigest5::Code digest;
			md5.Encode( buffer, digest );
			pdu.SetAuthenticator( (const BYTE*)&digest );
#endif
			return;
		}
	}

	PRandom random;
	pdu.SetRandomAuthenticator(random);
}

void RadiusClient::EncryptPasswords( 
	RadiusPDU& pdu, 
	const PString& secret,
	PMessageDigest5& md5 
	) const
{
	const PINDEX secretLength = secret.GetLength();
	PBYTEArray vector( secretLength + RadiusPDU::AuthenticatorLength );
	
	if( secretLength > 0 )
		memcpy( vector.GetPointer(secretLength), 
			(const char*)secret, secretLength 
			);
			
	RadiusAttr::List& attributes = pdu.GetAttributes();
	
	const PINDEX numAttrs = attributes.GetSize();
	
	for( PINDEX i = 0; i < numAttrs; i++ ) {
		RadiusAttr* attr = (RadiusAttr*)(attributes.GetAt(i));
		if( !(attr && attr->IsValid()) )
			continue;
		
		if( attr->GetType() != RadiusAttr::UserPassword	)
			continue;
			
		pdu.GetAuthenticator(vector,secretLength);

#if HAS_NEW_MD5		
		PMessageDigest::Result digest;
#else
		PMessageDigest5::Code digest;
#endif	
		md5.Encode(vector,digest);
		
		PINDEX pwdLength = attr->GetValueLength();
		pwdLength = (pwdLength==0) ? 16 : ((pwdLength+15) & (~((PINDEX)0xf)));
		
		PBYTEArray password( pwdLength );
			
		memset(password.GetPointer(pwdLength),0,pwdLength);
		attr->GetValue(password);
		
		DWORD* buf1ptr = (DWORD*)(password.GetPointer(pwdLength));
#if HAS_NEW_MD5
		const DWORD* buf2ptr = (const DWORD*)digest.GetPointer();
#else
		const DWORD* buf2ptr = (const DWORD*)&digest;
#endif

		if( (reinterpret_cast<unsigned long>(buf2ptr) & 3) 
			|| (reinterpret_cast<unsigned long>(buf1ptr) & 3) ) {
			for (int _i = 0; _i < 16; _i++)
				((BYTE*)buf1ptr)[_i] = ((BYTE*)buf1ptr)[_i] ^ ((const BYTE*)buf2ptr)[_i];
			buf1ptr += 4;
			buf2ptr += 4;
		} else {
			// dword aligned data
			*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
			*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
			*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
			*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
		}
		
		pwdLength -= (pwdLength<16) ? pwdLength : 16;
		
		while( pwdLength > 0 ) {
			memcpy(	vector.GetPointer(secretLength+16)+secretLength,
				buf1ptr-4, 16
				);
			
			md5.Encode(vector,digest);
#if HAS_NEW_MD5
			buf2ptr = (const DWORD*)digest.GetPointer();
#else
			buf2ptr = (const DWORD*)&digest;
#endif
			if( (reinterpret_cast<unsigned long>(buf2ptr) & 3) 
				|| (reinterpret_cast<unsigned long>(buf1ptr) & 3) ) {
				for (int _i = 0; _i < 16; _i++)
					((BYTE*)buf1ptr)[_i] = ((BYTE*)buf1ptr)[_i] ^ ((const BYTE*)buf2ptr)[_i];
				buf1ptr += 4;
				buf2ptr += 4;
			} else {
				// dword aligned data
				*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
				*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
				*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
				*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
			}
			
			pwdLength -= (pwdLength<16) ? pwdLength : 16;
		}
		
		(*attr) = RadiusAttr( RadiusAttr::UserPassword,
			password.GetPointer(), password.GetSize()
			);
	}
}

BOOL RadiusClient::GetSocket( RadiusSocket*& socket, unsigned char& id )
{
	RadiusSocket* s = NULL;

	PINDEX i;
	PINDEX emptySocketIndex = P_MAX_INDEX;
	
	for( i = 0; i < activeSockets.GetSize(); i++ )
		if( activeSockets.GetAt(i) ) {
			const PINDEX _id = activeSockets.GetAt(i)->GenerateNewId();
			if( _id == P_MAX_INDEX )
				continue;
			else {
				s = activeSockets.GetAt(i);
				id = (unsigned char)(_id & 0xff);
				break;
			}
		} else
			emptySocketIndex = i;
			
	const PTime now;
	PINDEX j = 0;
	
	while( j < activeSockets.GetSize() ) {
		if( j == i ) {
			j++;
			continue;
		}
		
		RadiusSocket* rsock = activeSockets.GetAt(j);
		if( rsock ) {
			rsock->RefreshIdCache(now.GetTimeInSeconds());
			if( rsock->CanDestroy() 
				&& ((rsock->GetRecentRequestTime() + socketDeleteTimeout) < now) )
			{
				activeSockets.SetAt(j,NULL);
				delete rsock;
				if( emptySocketIndex == P_MAX_INDEX )
					emptySocketIndex = j;
			}
		} else if( emptySocketIndex == P_MAX_INDEX )
			emptySocketIndex = j;
		j++;
	}

	if( s != NULL ) {
		socket = s;
		return TRUE;	
	}

	PRandom random;
	PINDEX randCount = (unsigned)(portMax-portBase+1) / 3;
	
	if( randCount > 0 )
		do {
			PINDEX portIndex = random % (unsigned)(portMax-portBase+1);

			delete s;
			s = NULL;

			if( localAddress == INADDR_ANY )
				s = CreateSocket( (WORD)(portBase + portIndex) );
			else
				s = CreateSocket( localAddress, (WORD)(portBase + portIndex) );
		} while( ((s == NULL) || (!s->IsOpen())) && (--randCount) );

	if( (s == NULL) || (!s->IsOpen()) )
		for( WORD p = portBase; p < portMax; p++ ) {
			delete s;
			s = NULL;

			if( localAddress == INADDR_ANY )
				s = CreateSocket( p );
			else
				s = CreateSocket( localAddress, p );
				
			if( s->IsOpen() )
				break;
		}
			
	if( s == NULL )
		return FALSE;
		
	if( !s->IsOpen() ) {
		delete s;
		return FALSE;
	}
		
	s->SetReadTimeout(requestTimeout);
	s->SetWriteTimeout(requestTimeout);
	s->SetIdCacheTimeout(idCacheTimeout);

	PTRACE(5,"RADIUS\tCreated new RADIUS client socket: "<<(*s));

	if( emptySocketIndex != P_MAX_INDEX )
		activeSockets.SetAt(emptySocketIndex,s);
	else
		activeSockets.SetAt(activeSockets.GetSize(),s);
	
	i = s->GenerateNewId();
	if( i == P_MAX_INDEX )
		return FALSE;
		
	socket = s;
	id = (unsigned char)(i & 0xff);

	return TRUE;
}

void RadiusClient::SetSocketDeleteTimeout(
	const PTimeInterval& timeout /// new timeout
	)
{
	PWaitAndSignal lock( socketMutex );

	if( timeout > PTimeInterval(20000) )	
		socketDeleteTimeout = timeout;
}

RadiusPDU* RadiusClient::BuildPDU( 
		const void* rawData, /// raw data buffer
		PINDEX rawLength /// length of the raw data buffer
		) const
{
	return new RadiusPDU( rawData, rawLength );
}

RadiusPDU* RadiusClient::BuildPDU() const
{
	return new RadiusPDU();
}

RadiusSocket* RadiusClient::CreateSocket( 
	const PIPSocket::Address& addr, 
	WORD port
	)
{
	return new RadiusSocket( *this, addr, port );
}
	
RadiusSocket* RadiusClient::CreateSocket( 
	WORD port
	)
{
	return new RadiusSocket( *this, port );
}

#endif /* HAS_RADIUS */
