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
#include <ptlib.h>
#include <ptlib/sockets.h>
#include <ptclib/random.h>
#include <ptclib/cypher.h>

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
	memset(&data,0,sizeof(data));
}

RadiusAttr::RadiusAttr(
	const RadiusAttr& attr
	)
{
	memcpy(&data,&(attr.data),sizeof(data));
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

	PAssert(valueLength<=MaxValueLength,PInvalidParameter);

	if( valueLength > MaxValueLength )
		valueLength = MaxValueLength;

	if( valueLength > 0 )
	{
		data[1] += valueLength;
		if( attrValue != NULL )
			memcpy(&(data[FixedHeaderLength]),attrValue,valueLength);
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
	
	PAssert(valueLength<=VsaMaxRfc2865ValueLength,PInvalidParameter);

	if( valueLength > VsaMaxRfc2865ValueLength )
		valueLength = VsaMaxRfc2865ValueLength;
	
	if( valueLength > 0 )
	{
		data[1] += valueLength;
		data[VsaFixedHeaderLength+1] += valueLength;
		if( attrValue != NULL )
			memcpy(&(data[VsaRfc2865FixedHeaderLength]),attrValue,valueLength);
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

	if( attrLength > 0 )
	{
		data[1] += attrLength;
		memcpy(&(data[FixedHeaderLength]),(const char*)stringValue,attrLength);
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
	const PTime& timeValue /// timestamp to be stored in the attribute Value
	)
{
	data[0] = attrType;
	data[1] = FixedHeaderLength + 4;

	if( attrType == VendorSpecific )
		PAssertAlways( PInvalidParameter );

	const DWORD tv = (DWORD)(timeValue.GetTimeInSeconds());
	
	data[FixedHeaderLength+0] = (BYTE)((tv>>24) & 0xff);
	data[FixedHeaderLength+1] = (BYTE)((tv>>16) & 0xff);
	data[FixedHeaderLength+2] = (BYTE)((tv>>8) & 0xff);
	data[FixedHeaderLength+3] = (BYTE)(tv & 0xff);
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
	
	PAssert(vsaLength<=VsaMaxRfc2865ValueLength,PInvalidParameter);
	if( vsaLength > VsaMaxRfc2865ValueLength )
		vsaLength = VsaMaxRfc2865ValueLength;

	if( vsaLength > 0 )
	{
		data[1] += vsaLength;
		data[VsaFixedHeaderLength+1] += vsaLength;
		
		memcpy( &(data[VsaRfc2865FixedHeaderLength]),
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
	const PTime& timeValue, /// 32 bit timestamp to be stored in the attribute value
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

	const DWORD tv = (DWORD)(timeValue.GetTimeInSeconds());
	
	data[VsaRfc2865FixedHeaderLength+0] = (BYTE)((tv>>24) & 0xff);
	data[VsaRfc2865FixedHeaderLength+1] = (BYTE)((tv>>16) & 0xff);
	data[VsaRfc2865FixedHeaderLength+2] = (BYTE)((tv>>8) & 0xff);
	data[VsaRfc2865FixedHeaderLength+3] = (BYTE)(tv & 0xff);
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
	
	data[VsaRfc2865FixedHeaderLength+0] = ((const BYTE*)&addr)[0];
	data[VsaRfc2865FixedHeaderLength+1] = ((const BYTE*)&addr)[1];
	data[VsaRfc2865FixedHeaderLength+2] = ((const BYTE*)&addr)[2];
	data[VsaRfc2865FixedHeaderLength+3] = ((const BYTE*)&addr)[3];
}

RadiusAttr::RadiusAttr(
	const void* rawData, /// buffer with the attribute raw data
	PINDEX rawLength /// length (bytes) of the buffer
	)
{
	memset(&data,0,sizeof(data));
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

	const PINDEX len = (PINDEX)data[1] & 0xff;
	memcpy( buffer.GetPointer(offset+len) + offset, &data, len );
	written = len;

	return TRUE;
}

BOOL RadiusAttr::Read( const void* rawData, PINDEX rawLength )
{
	memset(&data,0,sizeof(data));

	PAssertNULL(rawData);
	PAssert(rawLength>=FixedHeaderLength,PInvalidParameter);

	if( (rawData == NULL) || (rawLength < FixedHeaderLength) )
		return FALSE;

	const PINDEX len = (PINDEX)(((const BYTE*)rawData)[1]) & 0xff;
	
	if( (len < FixedHeaderLength) || (len > rawLength)
		|| ( ((PINDEX)((const BYTE*)rawData)[0] == VendorSpecific)
			&& (len < VsaFixedHeaderLength) ) )
		return FALSE;

	memcpy(&data,rawData,len);

	return TRUE;
}

void RadiusAttr::PrintOn(
	ostream &strm   /// Stream to print the object into.
    ) const
{
	const int indent = strm.precision() + 2;

	if( !IsValid() )
	{
		strm << "(Invalid) {\n";
		if( ((PINDEX)data[1] & 0xff) > 0 )
		{
			const _Ios_Fmtflags flags = strm.flags();

			const PBYTEArray value( (const BYTE*)&data, (PINDEX)(data[1]) & 0xff, FALSE );

			strm << hex << setfill('0') << resetiosflags(ios::floatfield)
				<< setprecision(indent) << setw(16);

			if( (value.GetSize() <= 32) || ((flags&ios::floatfield) != ios::fixed) )
				strm << value << '\n';
			else 
			{
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
	strm << setw(indent+7) << "type = " << (unsigned)data[0]
		<< " (" << PMAP_ATTR_TYPE_TO_NAME((PINDEX)data[0] & 0xff) << ")\n";
#else
	strm << setw(indent+7) << "type = " << (unsigned)data[0] << '\n';
#endif
	const PINDEX totalLen = (PINDEX)data[1] & 0xff;
	
	strm << setw(indent+9) << "length = " << totalLen << " octets\n";
	
	if( !IsVsa() )
	{
		const _Ios_Fmtflags flags = strm.flags();

		const PINDEX valueLen = (totalLen<=FixedHeaderLength) 
			? 0 : (totalLen-FixedHeaderLength);

		const PBYTEArray value( (const BYTE*)&(data[FixedHeaderLength]), valueLen, FALSE );

		strm << setw(indent+8) << "value = " << value.GetSize() << " octets {\n";
		strm << hex << setfill('0') << resetiosflags(ios::floatfield)
			<< setprecision(indent+2) << setw(16);

		if( value.GetSize() > 0 )
		{
			if( (value.GetSize() <= 32) || ((flags&ios::floatfield) != ios::fixed) )
				strm << value << '\n';
			else 
			{
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
	else
	{
		strm << setw(indent+11) << "vendorId = " 
			<< GetVsaVendorId() << '\n';

		const _Ios_Fmtflags flags = strm.flags();

		const PINDEX valueLen = (totalLen<=VsaFixedHeaderLength)
			? 0 : (totalLen-VsaFixedHeaderLength);

		const PBYTEArray value( (const BYTE*)&(data[VsaFixedHeaderLength]), valueLen, FALSE );

		strm << setw(indent+14) << "vendorValue = " << value.GetSize() << " octets {\n";
		strm << hex << setfill('0') << resetiosflags(ios::floatfield)
			<< setprecision(indent+2) << setw(16);

		if( value.GetSize() > 0 )
		{
			if( (value.GetSize() <= 32) || ((flags&ios::floatfield) != ios::fixed) )
				strm << value << '\n';
			else 
			{
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

BOOL RadiusAttr::IsValid() const
{
	return ((unsigned)data[0] == VendorSpecific) 
		? (((PINDEX)data[1] & 0xff) >= VsaFixedHeaderLength) 
		: (((PINDEX)data[1] & 0xff) >= FixedHeaderLength);
}

PINDEX RadiusAttr::GetVsaValueLength() const
{
	PINDEX len = (PINDEX)data[1] & 0xff;
	len = (len<=VsaRfc2865FixedHeaderLength) 
		? 0 : (len-VsaRfc2865FixedHeaderLength);
	
	PINDEX len2 = 0;
	if( len > 0 )
	{
		len2 = (PINDEX)data[VsaFixedHeaderLength+1] & 0xff;
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
		memcpy(
			buffer.GetPointer(offset+len)+offset,
			&(data[IsVsa()?VsaFixedHeaderLength:FixedHeaderLength]),
			len
			);
		
	return TRUE;
}

BOOL RadiusAttr::GetVsaValue( PBYTEArray& buffer, PINDEX offset ) const
{
	if( !(IsValid() && IsVsa()) )
		return FALSE;
		
	const PINDEX len = GetVsaValueLength();

	if( len > 0 )	
		memcpy(
			buffer.GetPointer(len+offset)+offset,
			&(data[VsaRfc2865FixedHeaderLength]),
			len
			);
		
	return TRUE;
}

PString RadiusAttr::AsString() const
{
	if( !IsValid() )
		return PString();

	const PINDEX len = (PINDEX)data[1] & 0xff;
	const PINDEX headerLen = ((PINDEX)data[0] == VendorSpecific) 
			? VsaFixedHeaderLength : FixedHeaderLength;

	if( len <= headerLen )
		return PString();
	else
		return PString( &(data[headerLen]), len-headerLen );
}

int RadiusAttr::AsInteger() const
{
	if( (((PINDEX)data[1] & 0xff) < (FixedHeaderLength+4)) 
		|| ((PINDEX)data[0] == VendorSpecific) )
		return 0;
	
	DWORD val = 0;
	
	val |= ((DWORD)(data[FixedHeaderLength+0]) << 24);
	val |= ((DWORD)(data[FixedHeaderLength+1]) << 16);
	val |= ((DWORD)(data[FixedHeaderLength+2]) << 8);
	val |= (DWORD)(data[FixedHeaderLength+3]);
	
	return val;
}

PTime RadiusAttr::AsTime() const
{
	if( (((PINDEX)data[1] & 0xff) < (FixedHeaderLength+4)) 
		|| ((PINDEX)data[0] == VendorSpecific) )
		return 0;
	
	DWORD val = 0;
	
	val |= ((DWORD)(data[FixedHeaderLength+0]) << 24);
	val |= ((DWORD)(data[FixedHeaderLength+1]) << 16);
	val |= ((DWORD)(data[FixedHeaderLength+2]) << 8);
	val |= (DWORD)(data[FixedHeaderLength+3]);
	
	return val;
}


PIPSocket::Address RadiusAttr::AsAddress() const
{
	if( (((PINDEX)data[1] & 0xff) < (FixedHeaderLength+4)) 
		|| ((PINDEX)data[0] == VendorSpecific) )
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
	if( (!IsValid()) || ((PINDEX)data[0] != VendorSpecific) )
		return PString();
		
	const PINDEX len = (PINDEX)data[1] & 0xff;

	if( len <= VsaRfc2865FixedHeaderLength )
		return PString();
	else
		return PString( &(data[VsaRfc2865FixedHeaderLength]), len-VsaRfc2865FixedHeaderLength );
}

unsigned char RadiusAttr::GetVsaType() const
{
	if( ((PINDEX)data[1] & 0xff) < VsaRfc2865FixedHeaderLength )
		return 0;
		
	return data[VsaFixedHeaderLength+0];
}

int RadiusAttr::AsVsaInteger() const
{
	if( (((PINDEX)data[1] & 0xff) < (VsaRfc2865FixedHeaderLength+4)) 
		|| ((PINDEX)data[0] != VendorSpecific) )
		return 0;
		
	DWORD val = 0;
	
	val |= ((DWORD)(data[VsaRfc2865FixedHeaderLength+0]) << 24);
	val |= ((DWORD)(data[VsaRfc2865FixedHeaderLength+1]) << 16);
	val |= ((DWORD)(data[VsaRfc2865FixedHeaderLength+2]) << 8);
	val |= (DWORD)(data[VsaRfc2865FixedHeaderLength+3]);
	
	return val;
}

PTime RadiusAttr::AsVsaTime() const
{
	if( (((PINDEX)data[1] & 0xff) < (VsaRfc2865FixedHeaderLength+4)) 
		|| ((PINDEX)data[0] != VendorSpecific) )
		return 0;
	
	DWORD val = 0;
	
	val |= ((DWORD)(data[VsaRfc2865FixedHeaderLength+0]) << 24);
	val |= ((DWORD)(data[VsaRfc2865FixedHeaderLength+1]) << 16);
	val |= ((DWORD)(data[VsaRfc2865FixedHeaderLength+2]) << 8);
	val |= (DWORD)(data[VsaRfc2865FixedHeaderLength+3]);

	return val;
}

PIPSocket::Address RadiusAttr::AsVsaAddress() const
{
	if( (((PINDEX)data[1] & 0xff) < (VsaRfc2865FixedHeaderLength+4)) 
		|| ((PINDEX)data[0] != VendorSpecific) )
		return 0;
		
	DWORD val = 0;
	
	((BYTE*)&val)[0] = data[VsaRfc2865FixedHeaderLength+0];
	((BYTE*)&val)[1] = data[VsaRfc2865FixedHeaderLength+1];
	((BYTE*)&val)[2] = data[VsaRfc2865FixedHeaderLength+2];
	((BYTE*)&val)[3] = data[VsaRfc2865FixedHeaderLength+3];
	
	return val;
}

PObject::Comparison RadiusAttr::Compare(
	const PObject & obj   // Object to compare against.
	) const
{
	if( !obj.IsDescendant(RadiusAttr::Class()) )
	{
		PAssertAlways(PInvalidCast);
		return GreaterThan;
	}

	if( !(IsValid() && ((const RadiusAttr&)obj).IsValid()) )
	{
		PAssertAlways(PInvalidParameter);
		return GreaterThan;
	}
	
	const PINDEX thisType = (PINDEX)data[0] & 0xff;
	const PINDEX attrType = (PINDEX)(((const RadiusAttr&)obj).data[0]) & 0xff;
	
	if( thisType > attrType )
		return GreaterThan;
	else if( thisType < attrType )
		return LessThan;
	else
	{
		const PINDEX thisLen = (PINDEX)data[1] & 0xff;
		const PINDEX attrLen = (PINDEX)(((const RadiusAttr&)obj).data[1]) & 0xff;
		
		if( (thisType == VendorSpecific) && (thisLen >= VsaFixedHeaderLength) 
			&& (attrLen >= VsaFixedHeaderLength) )
		{
			const DWORD thisVendorId = GetVsaVendorId();
			const DWORD objVendorId = ((const RadiusAttr&)obj).GetVsaVendorId();
			
			if( thisVendorId > objVendorId )
				return GreaterThan;
			else if( thisVendorId < objVendorId )
				return LessThan;
			else
			{
				if( (thisLen >= VsaRfc2865FixedHeaderLength) 
					&& (attrLen >= VsaRfc2865FixedHeaderLength) )
				{
					const DWORD thisVsaType = GetVsaType();
					const DWORD objVsaType = ((const RadiusAttr&)obj).GetVsaType();
					
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
	const PINDEX thisLen = (PINDEX)data[1] & 0xff;
	const PINDEX attrLen = (PINDEX)(attr.data[1] & 0xff);
	
	if( thisLen < attrLen )
		return LessThan;
	else if( thisLen > attrLen )
		return GreaterThan;
	else
	{
		if( thisLen == 0 )
			return EqualTo;
		
		const int result = memcmp(&data,&(attr.data),thisLen);

		return (result==0) ? EqualTo : ((result>0) ? GreaterThan : LessThan);
	}
}



RadiusPDU::RadiusPDU()
	:
	code( 0 ),
	id( 0 )
{
	memset(&authenticator,0,sizeof(authenticator));
}

RadiusPDU::RadiusPDU( 
	const RadiusPDU& pdu 
	)
	:
	code( pdu.code ),
	id( pdu.id )
{
	memcpy(&authenticator,&(pdu.authenticator),sizeof(authenticator));
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
	memset(&authenticator,0,sizeof(authenticator));
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
	memset(&authenticator,0,sizeof(authenticator));
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
	if( !Read(rawData,rawLength) )
	{
		memset(&authenticator,0,sizeof(authenticator));
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
	
	for( PINDEX i = 0; i < attributes.GetSize(); i++ )
	{
		const RadiusAttr* const attr = (RadiusAttr*)(attributes.GetAt(i));
		if( attr && attr->IsValid() )
			len += attr->GetLength();
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
	{
		strm << setw(indent+22) << "attributes = <<null>>\n";
	}
	else
	{
		strm << setw(indent+13) << "attributes = " << attributes.GetSize() << " elements {\n";

		const int aindent = indent + 2;

		for( PINDEX i = 0; i < attributes.GetSize(); i++ )
		{
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
	
	for( PINDEX i = 0; i < attributes.GetSize(); i++ )
	{
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
	memcpy(
		vector.GetPointer(offset+AuthenticatorLength)+offset,
		&authenticator,
		AuthenticatorLength
		);
}

BOOL RadiusPDU::SetAuthenticator( const PBYTEArray& vector, PINDEX offset )
{
	PINDEX len = vector.GetSize();
	
	if( offset >= len )
		return FALSE;

	len -= offset;

	if( len > 0 )
		memcpy(
			&authenticator,
			((const BYTE*)vector)+offset,
			((len<AuthenticatorLength)?len:AuthenticatorLength)
			);

	return TRUE;
}

BOOL RadiusPDU::SetAuthenticator( const void* data )
{
	PAssertNULL(data);
	if( data == NULL )
		return FALSE;

	memcpy(&authenticator,data,AuthenticatorLength);
	return TRUE;
}

void RadiusPDU::SetRandomAuthenticator( PRandom& random )
{
	unsigned r = random;
	BYTE* rptr = (BYTE*)&r;

	authenticator[0] = rptr[0];
	authenticator[1] = rptr[1];
	authenticator[2] = rptr[2];
	authenticator[3] = rptr[3];
	
	r = random;
	
	authenticator[4] = rptr[0];
	authenticator[5] = rptr[1];
	authenticator[6] = rptr[2];
	authenticator[7] = rptr[3];
	
	r = random;
	
	authenticator[8] = rptr[0];
	authenticator[9] = rptr[1];
	authenticator[10] = rptr[2];
	authenticator[11] = rptr[3];
	
	r = random;
	
	authenticator[12] = rptr[0];
	authenticator[13] = rptr[1];
	authenticator[14] = rptr[2];
	authenticator[15] = rptr[3];
}

BOOL RadiusPDU::AppendAttribute( RadiusAttr* attr )
{
	PAssertNULL(attr);
	if( !(attr && attr->IsValid()) )
		return FALSE;

	return attributes.Append( attr ) != P_MAX_INDEX;
}

BOOL RadiusPDU::AppendAttributes( const RadiusAttr::List& list )
{
	const PINDEX lsize = list.GetSize();
	
	for( PINDEX i = 0; i < lsize; i++ )
	{
		const RadiusAttr* const attr = (const RadiusAttr*)(list.GetAt(i));
		if( attr && attr->IsValid() )
			AppendAttribute( (RadiusAttr*)(attr->Clone()) );
	}
			
	return TRUE;
}

PINDEX RadiusPDU::FindAttribute(
	unsigned char attrType, /// attribute type to be matched
	PINDEX offset /// start element for the search operation
	) const
{
	const PINDEX numAttrs = attributes.GetSize();
	const RadiusAttr destAttr(attrType,(void*)NULL,0);
	for( PINDEX i = offset; i < numAttrs; i++ )
	{
		const RadiusAttr* attr = (const RadiusAttr*)(attributes.GetAt(i));
		if( attr && (attr->Compare(destAttr) == EqualTo) )
			return i;
	}
	return P_MAX_INDEX;
}
		
PINDEX RadiusPDU::FindAttribute(
	int vendorId, /// vendor identifier to be matched
	unsigned char vendorType, /// vendor attribute type to be matched
	PINDEX offset /// start element for the search operation
	) const
{
	const PINDEX numAttrs = attributes.GetSize();
	const RadiusAttr destAttr(NULL,0,vendorId,vendorType);
	for( PINDEX i = offset; i < numAttrs; i++ )
	{
		const RadiusAttr* attr = (const RadiusAttr*)(attributes.GetAt(i));
		if( attr && (attr->Compare(destAttr) == EqualTo) )
			return i;
	}
	return P_MAX_INDEX;
}

RadiusAttr* RadiusPDU::GetAttributeAt(
	PINDEX index /// index of the attribute to be retrieved
	) const
{
	if( index < attributes.GetSize() )
		return (RadiusAttr*)(attributes.GetAt(index));
	return NULL;
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

	memcpy(buffptr,&authenticator,AuthenticatorLength);
	buffptr += AuthenticatorLength;

	written = FixedHeaderLength;

	const PINDEX numAttributes = attributes.GetSize();
	
	for( PINDEX i = 0; i < numAttributes; i++ )
	{
		PINDEX writtenA = 0;
		if( !attributes[i].Write(buffer,writtenA,written+offset) )
			return FALSE;
		written += writtenA;
	}

	return TRUE;
}

BOOL RadiusPDU::Read( const void* rawData, PINDEX rawLength )
{
	PAssertNULL(rawData);
	PAssert( rawLength >= MinPduLength, PInvalidParameter );

	code = id = 0;

	if( (rawData == NULL) || (rawLength < MinPduLength) )
		return FALSE;

	const BYTE* buffptr = (const BYTE*)rawData;

	code = *buffptr++;
	id = *buffptr++;

	const PINDEX length = (((PINDEX)(*buffptr) & 0xff) << 8) 
		| ((PINDEX)(*(buffptr+1)) & 0xff);

	buffptr += 2;
	
	if( (length > rawLength) || (length < MinPduLength) )
	{
		code = id = 0;
		return FALSE;
	}

	memcpy(&authenticator,buffptr,AuthenticatorLength);
	buffptr += AuthenticatorLength;

	attributes.RemoveAll();

	PINDEX currentPosition = FixedHeaderLength;

	while( currentPosition < length )
	{
		RadiusAttr* attr = BuildAttribute( 
			buffptr,
			length - currentPosition
			);
		
		if( !(attr && attr->IsValid()) )
		{
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
	memcpy(
		&authenticator,
		&(pdu.authenticator),
		AuthenticatorLength
		);

	attributes = pdu.attributes;
	attributes.MakeUnique();
	
	return TRUE;
}

#define DEFAULT_PERMANENT_SYNCPOINTS 8

RadiusSocket::RadiusSocket( 
	RadiusClient& client,
	WORD port 
	)
	:
	PUDPSocket( port ),
	permanentSyncPoints( DEFAULT_PERMANENT_SYNCPOINTS ),
	readBuffer( RadiusPDU::MaxPduLength ),
	isReading( FALSE ),
	nestedCount( 0 ),
	idCacheTimeout( RadiusClient::DefaultIdCacheTimeout ),
	radiusClient( client )
{
	int i;
	PRandom random;
	const unsigned _id_ = random;
	oldestId = nextId = (BYTE)(_id_^(_id_>>8)^(_id_>>16)^(_id_>>24));

	for( i = 0; i < 256; i++ )
		readSyncPoints[i] = 0;
		
	if( IsOpen() )
	{
		for( i = 0; i < 256; i++ )
			pendingRequests[i] = 0;
		for( i = 0; i < 8; i++ )
			syncPointMap[i] = 0;
		for( i = 0; i < 256; i++ )
			idTimestamps[i] = 0;

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
	PUDPSocket( port ),
	permanentSyncPoints( DEFAULT_PERMANENT_SYNCPOINTS ),
	readBuffer( RadiusPDU::MaxPduLength ),
	isReading( FALSE ),
	nestedCount( 0 ),
	idCacheTimeout( RadiusClient::DefaultIdCacheTimeout ),
	radiusClient( client )
{
	Close();
	Listen(addr,1,port);
	
	int i;
	PRandom random;
	const unsigned _id_ = random;
	oldestId = nextId = (BYTE)(_id_^(_id_>>8)^(_id_>>16)^(_id_>>24));

	for( i = 0; i < 256; i++ )
		readSyncPoints[i] = 0;

	if( IsOpen() )
	{
		for( i = 0; i < 256; i++ )
			pendingRequests[i] = 0;
		for( i = 0; i < 8; i++ )
			syncPointMap[i] = 0;
		for( i = 0; i < 256; i++ )
			idTimestamps[i] = 0;

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
	{
		delete readSyncPoints[i];
		readSyncPoints[i] = NULL;
	}
}

void RadiusSocket::PrintOn( ostream& strm ) const
{
	strm<<"port"<<':'<<GetPort()<<':'<<'['<<nestedCount<<','
		<<(PINDEX)oldestId<<'-'<<(PINDEX)nextId<<']';
}

PINDEX RadiusSocket::AllocReadSyncPoint()
{
	PINDEX idx = 0;
	
	for( PINDEX k = 0; k < 8; k++ )
		if( syncPointMap[k] != 0xffffffff )
		{
			for( PINDEX i = 0, j = 1; i < 32; i++, j <<= 1, idx++ )
				if( (syncPointMap[k] & ((DWORD)j)) == 0 )
				{
					syncPointMap[k] |= (DWORD)j;
					if( readSyncPoints[idx] == NULL )
						readSyncPoints[idx] = new PSyncPoint();
					return idx;
				}
		}
		else
			idx += 32;
			
	return P_MAX_INDEX;
}

void RadiusSocket::FreeReadSyncPoint( PINDEX syncPointIndex )
{
	if( (syncPointIndex < 256) && (syncPointIndex != P_MAX_INDEX) )
	{
		syncPointMap[(syncPointIndex >> 5) & 7] 
			&= ~(((DWORD)1)<<(syncPointIndex & 31));
		if( syncPointIndex >= permanentSyncPoints )
		{
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
	ReadInfo* readInfo = NULL;

	{
		if( !readMutex.Wait( timeout ) )
			return FALSE;

		PWaitAndSignal lock( readMutex, FALSE );

		if( pendingRequests[id] != NULL )
		{
			PTRACE(4,"RADIUS\tDuplicate RADIUS socket read request (id:" 
				<<(PINDEX)id<<')'
				);
			return FALSE;
		}

		if( !isReading )
			isReading = shouldRead = TRUE;
		else
		{
			const PINDEX index = AllocReadSyncPoint();
			if( index == P_MAX_INDEX )
				return FALSE;
			syncPoint = readSyncPoints[index];
			if( syncPoint == NULL )
			{
				FreeReadSyncPoint(index);
				return FALSE;
			}
			readSyncPointIndices[id] = index;
			nestedCount++;
		}
		
		readInfo = pendingRequests[id] 
			= new ReadInfo( pdu, sendBuffer, length, 
				&serverAddress, serverPort 
				);
	}

	BOOL result = WriteTo( sendBuffer, length, serverAddress, serverPort );
	if( !result )
		PTRACE(5,"RADIUS\tSend UDP packet error - code: "
			<<GetErrorCode(LastWriteError)<<", number: "
			<<GetErrorNumber(LastWriteError)
			);
	else
	do
	{
		result = FALSE;
		
		if( shouldRead )
		{
			PIPSocket::Address remoteAddress;
			WORD remotePort;

			result = ReadFrom( readBuffer.GetPointer(readBuffer.GetSize()), 
				readBuffer.GetSize(), remoteAddress, remotePort 
				);
			if( !result )
				break;
			
			result = FALSE;
				
			PINDEX bytesRead = GetLastReadCount();

			if( bytesRead < RadiusPDU::MinPduLength )
			{
				PTRACE(5,"RADIUS\tReceived packet is too small ("
					<< bytesRead << ')'
					);
				continue;
			}
	
			PINDEX len = (((PINDEX)(((const BYTE*)readBuffer)[2]) & 0xff)<<8)
				| ((PINDEX)(((const BYTE*)readBuffer)[3]) & 0xff);
				
			if( (len < RadiusPDU::MinPduLength) || (len > RadiusPDU::MaxPduLength) )
			{
				PTRACE(5,"RADIUS\tReceived packet has invalid size (" 
					<<len<<')' 
					); 
				continue;
			}

			if( len > bytesRead )
			{
				PTRACE(5,"RADIUS\tReceived packet is too small (" 
					<<bytesRead<<"), expected "<<len<<" octets"
					);
				continue;
			}
				
			if( !readMutex.Wait( timeout ) )
			{
				PTRACE(5,"RADIUS\tTimed out (mutex) - dropping PDU (id:"
					<<(PINDEX)(((const BYTE*)readBuffer)[1])
					);
				continue;
			}
				
			PWaitAndSignal lock( readMutex, FALSE );

			const BYTE newId = ((const BYTE*)readBuffer)[1];

			if( pendingRequests[newId] == NULL )
			{
				PTRACE(5,"RADIUS\tUnmatched PDU received (code:"
					<<(PINDEX)(((const BYTE*)readBuffer)[0])<<",id:"
					<<(PINDEX)newId<<')'
					);
				continue;
			}

			if( (remoteAddress != *(pendingRequests[newId]->address)) 
				|| (remotePort != pendingRequests[newId]->port) )
			{
				PTRACE(5,"RADIUS\tReceived PDU from unknown address: "
					<<remoteAddress<<':'<<remotePort
					);
				continue;
			}
			
			if( !radiusClient.VerifyResponseAuthenticator(
					pendingRequests[newId]->requestBuffer,
					pendingRequests[newId]->requestLength,
					(const BYTE*)readBuffer,
					len
					) )
			{
				PTRACE(5,"RADIUS\tPDU (id:"
					<<(PINDEX)((const BYTE*)readBuffer)[1]<<") received from "
					<<remoteAddress<<':'<<remotePort
					<<" has invalid response authenticator"
					);
				continue;
			}
				
			RadiusPDU* newPdu = radiusClient.BuildPDU( 
				(const BYTE*)readBuffer, len 
				);
				
			if( !(newPdu && newPdu->IsValid()) )
			{
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
					
			if( newId == id )
			{
				isReading = FALSE;

				if( nestedCount )
					for( PINDEX i = 0, j = oldestId; i < 256; i++, j = (++j) & 0xff )
						if( (readSyncPointIndices[j] != P_MAX_INDEX)
							&& (readSyncPoints[readSyncPointIndices[j] & 0xff] != NULL) )
						{
							readSyncPoints[readSyncPointIndices[j] & 0xff]->Signal();
							break;
						}
					
				delete readInfo;
				return TRUE;
			}
			else if( (readSyncPointIndices[newId] != P_MAX_INDEX)
				&& (readSyncPoints[readSyncPointIndices[newId]] != NULL ) )
			{
				readSyncPoints[readSyncPointIndices[newId]]->Signal();
				continue;
			}
		}
		else
		{
			result = (syncPoint != NULL) && syncPoint->Wait( timeout );
			if( !result )
				break;
				
			result = FALSE;
				
			PWaitAndSignal lock( readMutex );

			if( pendingRequests[id] == NULL )
			{
				FreeReadSyncPoint(readSyncPointIndices[id]);
				readSyncPointIndices[id] = P_MAX_INDEX;
				if( nestedCount )
					nestedCount--;
				delete readInfo;
				return TRUE;
			}

			if( !isReading )
			{
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
		
		if( readSyncPointIndices[id] != P_MAX_INDEX )
		{
			FreeReadSyncPoint(readSyncPointIndices[id]);
			readSyncPointIndices[id] = P_MAX_INDEX;
			if( nestedCount )
				nestedCount--;
		}

		if( isReading && shouldRead )
		{
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

	delete readInfo;
	return result;
}

void RadiusSocket::RefreshIdCache()
{
	const PTime now;
	const PINDEX lastId = ((nextId>=oldestId)?nextId:((PINDEX)nextId+256));
	
	for( PINDEX i = oldestId; i < lastId; i++ )
		if( (idTimestamps[i & 0xff] + idCacheTimeout) < now )
			oldestId = ++oldestId & 0xff;
		else
			break;
}

PINDEX RadiusSocket::GenerateNewId()
{
	RefreshIdCache();
	
	if( ((nextId + 1) & 0xff) == oldestId )
		return P_MAX_INDEX;
	else
	{
		const PTime now;
		recentRequestTime = idTimestamps[nextId] = now;
		nextId = ++nextId & 0xff;
		return nextId;
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
	if( PTrace::CanTrace(4) )
	{
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
		activeSockets[i].SetIdCacheTimeout( timeout );
			
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
	{
		activeSockets[i].SetReadTimeout( requestTimeout );
		activeSockets[i].SetWriteTimeout( requestTimeout );
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
	PBYTEArray sendBuffer( requestPDU.GetLength() );
		
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
		
		if( serverComponents.GetSize() < 1 )
		{
			PTRACE(1,"RADIUS\tEmpty RADIUS server entry no "<<serverIndex);
			return FALSE;
		}
		
		const PString serverName = serverComponents[0].Trim();
		
		if( serverComponents.GetSize() >= 2 )
			_authPort = serverComponents[1].AsUnsigned();
		if( serverComponents.GetSize() >= 3 )	
			_acctPort = serverComponents[2].AsUnsigned();
			
		if( _authPort == 0 )
			_authPort = authPort;
		if( _acctPort == 0 )
			_acctPort = acctPort;

		PIPSocket::Address serverAddress;
		const WORD serverPort 
			= IsAcctPDU(requestPDU)?_acctPort:_authPort;

		if( (!PIPSocket::GetHostAddress( serverName, serverAddress ))
			|| (!serverAddress.IsValid()) )
		{
			PTRACE(5,"RADIUS\tCould not get IPv4 address for RADIUS server host: "
				<< serverName
				);
			continue;
		}

		for( int j = 0; j < (roundRobinServers ? 1 : numRetries); j++ )
		{
			changed = FALSE;
			
			RadiusPDU* oldPDU = clonedRequestPDU;
			clonedRequestPDU = (RadiusPDU*)(requestPDU.Clone());
			
			if( !OnSendPDU(*clonedRequestPDU,retransmission,changed) )
			{
				delete clonedRequestPDU;
				delete oldPDU;
				return FALSE;					
			}
				
			if( changed || (!retransmission) )
			{
				delete oldPDU;
				
				{ 
					PWaitAndSignal lock( socketMutex );
		
					if( !GetSocket( socket, id ) )
					{
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
				if( !clonedRequestPDU->Write( sendBuffer, written ) )
				{
					delete clonedRequestPDU;
					return FALSE;
				}	
	
				if( written != length )
				{
					PTRACE(5,"RADIUS\tNumber of bytes written to the request PDU buffer ("
						<< written << ") does not match PDU length (" << length << ')'
						);
					delete clonedRequestPDU;
					return FALSE;
				}
			}
			else
			{
				delete clonedRequestPDU;
				clonedRequestPDU = oldPDU;
			}
			
			PTRACE(5,"RADIUS\tSending PDU to RADIUS server "
				<<serverName<<" ("<<serverAddress<<':'<<serverPort<<')'<<" from "
				<<(*socket)<<", PDU: "<<*clonedRequestPDU
				);
				
			RadiusPDU* response = NULL;
			
			retransmission = TRUE;
			
			if( !socket->MakeRequest( (const BYTE*)sendBuffer, length, 
					serverAddress, serverPort, response ) )
			{
				PTRACE(5,"RADIUS\tReceive response from RADIUS server failed (id:"
					<<(PINDEX)(clonedRequestPDU->GetId())<<')'
					);
				continue;
			}
			
			PTRACE(5,"RADIUS\tReceived PDU from RADIUS server "
				<<serverName<<" ("<<serverAddress<<':'<<serverPort<<')'
				<<" by socket "<<(*socket)<<", PDU: "
				<<(*response)
				);
				
			if( !OnReceivedPDU( *response ) )
			{
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

BOOL RadiusClient::VerifyResponseAuthenticator(
	const BYTE* requestBuffer,
	PINDEX requestLength,
	const BYTE* responseBuffer,
	PINDEX responseLength
	)
{
	if( responseLength < RadiusPDU::FixedHeaderLength )
		return FALSE;
	
	PMessageDigest5 md5;	
	PMessageDigest5::Code digest;

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
	
	md5.Complete( digest );
	
	return memcmp( 
		(const BYTE*)&digest, 
		((const BYTE*)responseBuffer) + RadiusPDU::AuthenticatorOffset,
		RadiusPDU::AuthenticatorLength
		) == 0;
}

BOOL RadiusClient::OnSendPDU( 
	RadiusPDU& pdu,
	BOOL retransmission,
	BOOL& changed
	)
{
	changed = changed || FALSE;
	return TRUE;
}

BOOL RadiusClient::OnReceivedPDU( RadiusPDU& pdu )
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
	return (port==0) ? DefaultAuthPort : port;
}

WORD RadiusClient::GetDefaultAcctPort()
{
	const WORD port = PSocket::GetPortByService( "udp", "radacct" );
	return (port==0) ? DefaultAcctPort : port;
}

void RadiusClient::FillRequestAuthenticator( 
	RadiusPDU& pdu, 
	const PString& secret,
	PMessageDigest5& md5 
	) const
{
	if( GetRAGenerator(pdu) == RAGeneratorMD5 )
	{
		const PINDEX pduLength = pdu.GetLength();
		const PINDEX secretLength = secret.GetLength();
		PBYTEArray buffer( pduLength + secretLength );

		PINDEX written;
		if( pdu.Write( buffer, written ) && (written == pduLength) )
		{
			memset(
				buffer.GetPointer(RadiusPDU::FixedHeaderLength)
					+ RadiusPDU::AuthenticatorOffset,
				0,
				RadiusPDU::AuthenticatorLength
				);

			if( secretLength > 0 )
				memcpy(
					buffer.GetPointer(written+secretLength)+written,
					(const char*)secret,
					secretLength
					);

			PMessageDigest5::Code digest;

			md5.Encode( buffer, digest );

			pdu.SetAuthenticator( (const BYTE*)&digest );
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
		memcpy( 
			vector.GetPointer(secretLength),
			(const char*)secret, 
			secretLength
			);
			
	RadiusAttr::List& attributes = pdu.GetAttributes();
	
	const PINDEX numAttrs = attributes.GetSize();
	
	for( PINDEX i = 0; i < numAttrs; i++ )
	{
		RadiusAttr* attr = (RadiusAttr*)(attributes.GetAt(i));
		if( !(attr && attr->IsValid()) )
			continue;
		
		if( attr->GetType() != RadiusAttr::UserPassword	)
			continue;
			
		pdu.GetAuthenticator(vector,secretLength);
		
		PMessageDigest5::Code digest;
		md5.Encode(vector,digest);
		
		PINDEX pwdLength = attr->GetValueLength();
		pwdLength = (pwdLength==0) ? 16 : ((pwdLength+15) & (~((PINDEX)0xf)));
		
		PBYTEArray password( pwdLength );
			
		memset(password.GetPointer(pwdLength),0,pwdLength);
		attr->GetValue(password);
		
		DWORD* buf1ptr = (DWORD*)(password.GetPointer(pwdLength));
		const DWORD* buf2ptr = (const DWORD*)&digest;
		
		*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
		*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
		*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
		*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
		
		pwdLength -= (pwdLength<16) ? pwdLength : 16;
		
		while( pwdLength > 0 )
		{
			memcpy(
				vector.GetPointer(secretLength+16)+secretLength,
				buf1ptr-4,
				16
				);
			md5.Encode(vector,digest);
			buf2ptr = (const DWORD*)&digest;
			
			*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
			*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
			*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
			*buf1ptr++ = *buf1ptr ^ *buf2ptr++;
			
			pwdLength -= (pwdLength<16) ? pwdLength : 16;
		}
		
		(*attr) = RadiusAttr(
			RadiusAttr::UserPassword,
			password.GetPointer(),
			password.GetSize()
			);
	}
}

BOOL RadiusClient::GetSocket( RadiusSocket*& socket, unsigned char& id )
{
	RadiusSocket* s = NULL;

	int i;	
	
	for( i = 0; i < activeSockets.GetSize(); i++ )
	{
		const PINDEX _id = (activeSockets[i]).GenerateNewId();
		if( _id == P_MAX_INDEX )
			continue;
		else
		{
			s = (RadiusSocket*)(activeSockets.GetAt(i));
			id = _id;
			break;
		}
	}

	const PTime now;
		
	int j = 0;
	while( j < activeSockets.GetSize() )
	{
		if( j == i )
		{
			j++;
			continue;
		}
		
		RadiusSocket* rsock = (RadiusSocket*)(activeSockets.GetAt(j));
		if( rsock == NULL )
		{
			j++;
			continue;
		}
		
		if( j < i )
		{
			if( rsock->CanDestroy() 
				&& ((rsock->GetRecentRequestTime() + socketDeleteTimeout) < now) )
			{
				activeSockets.RemoveAt(j);
				i--;
			}
			else
				j++;
			continue;
		}
		
		if( j > i )
		{
			rsock->RefreshIdCache();
			if( rsock->CanDestroy() 
				&& ((rsock->GetRecentRequestTime() + socketDeleteTimeout) < now) )
				activeSockets.RemoveAt(j);
			else
				j++;
			continue;
		}
		
		j++;
	}

	if( s != NULL )
	{
		socket = s;
		return TRUE;	
	}

	PRandom random;
	PINDEX randCount = (unsigned)(portMax-portBase+1) / 3;
	
	do
	{
		PINDEX portIndex = random % (unsigned)(portMax-portBase+1);

		delete s;
		s = NULL;

		if( localAddress == INADDR_ANY )
			s = CreateSocket( portBase + portIndex );
		else
			s = CreateSocket( localAddress, portBase + portIndex );
	} while( ((s == NULL) || (!s->IsOpen())) && (--randCount) );

	if( (s == NULL) || (!s->IsOpen()) )
		for( WORD p = portBase; p < portMax; p++ )
		{
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
		
	if( !s->IsOpen() )
	{
		delete s;
		return FALSE;
	}
		
	s->SetReadTimeout(requestTimeout);
	s->SetWriteTimeout(requestTimeout);
	s->SetIdCacheTimeout(idCacheTimeout);
	
	PTRACE(5,"RADIUS\tCreated new socket for RADIUS client: "<<(*s));
	
	activeSockets.Append(s);
	socket = s;
	id = s->GenerateNewId();
	return (id != P_MAX_INDEX);
}

void RadiusClient::SetSocketDeleteTimeout(
	const PTimeInterval& timeout /// new timeout
	)
{
	PWaitAndSignal lock( socketMutex );

	if( timeout > PTimeInterval(5000) )	
		socketDeleteTimeout = timeout;
}
