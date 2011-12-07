/*
 * radproto.cxx
 *
 * RADIUS protocol classes.
 *
 * Copyright (c) 2003, Quarcom FHU, Michal Zygmuntowicz
 * Copyright (c) 2003-2011, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if HAS_RADIUS

#include <ptlib.h>
#include <ptclib/cypher.h>
#include <ptclib/random.h>
#include "Toolkit.h"
#include "h323util.h"
#include "radproto.h"

// ignore overflow warnings
#if (!_WIN32) && (GCC_VERSION >= 40400)
#pragma GCC diagnostic ignored "-Wstrict-overflow"
#endif

namespace {
/// Human-readable attribute names
const char* const radiusAttributeNames[] =
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
/* 88*/	"Framed-Pool", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown",
/* RFC 3162 */
/* 95*/ "NAS-IPv6-Address", "Framed-Interface-Id", "Framed-IPv6-Prefix",
/* 98*/	"Login-IPv6-Host", "Framed-IPv6-Route", "Framed-IPv6-Pool",
/*101*/	"Unknown",
};

/// Human readable RADIUS packet code names
const char* const radiusPacketCodeNames[] =
{
/* 0*/ "Invalid", "Access-Request", "Access-Accept", "Access-Reject",
/* 4*/ "Accounting-Request", "Accounting-Response", "Unknown", "Unknown",
/* 8*/ "Unknown", "Unknown", "Access-Challenge", "Status-Server",
/*12*/ "Status-Client", "Unknown"
};

/** Macro that returns name associated with the given attribute type.
	Returns "Unknown" if the name is not defined.
*/
inline
const char* const PMAP_ATTR_TYPE_TO_NAME(unsigned type)
{
	return type >= sizeof(radiusAttributeNames)/sizeof(radiusAttributeNames[0])
		? radiusAttributeNames[sizeof(radiusAttributeNames)/sizeof(radiusAttributeNames[0])-1]
		: radiusAttributeNames[type];
}

/** Macro that returns name associated with the given RADIUS packet code.
	Returns "Unknown" if the name is not defined.
*/
inline
const char* const PMAP_CODE_TO_NAME(unsigned code)
{
	return code >= sizeof(radiusPacketCodeNames)/sizeof(radiusPacketCodeNames[0])
		? radiusPacketCodeNames[sizeof(radiusPacketCodeNames)/sizeof(radiusPacketCodeNames[0])-1]
		: radiusPacketCodeNames[code];
}


// Cisco VSA attributes together with names and name lengths for fast lookup
#define CISCO_ATTR_NAME(namestr) namestr, strlen(namestr)

struct CiscoAttrName {
	CiscoAttrName(const char* n, size_t l, unsigned char t) 
		: m_name(n), m_nameLen(l), m_type(t) {} // workaround for VC6
		
	const char* const m_name;
	size_t m_nameLen;
	unsigned char m_type;
} CiscoAttrNames[] = {
	CiscoAttrName(CISCO_ATTR_NAME("h323-remote-address"), RadiusAttr::CiscoVSA_h323_remote_address),
	CiscoAttrName(CISCO_ATTR_NAME("h323-conf-id"), RadiusAttr::CiscoVSA_h323_conf_id),
	CiscoAttrName(CISCO_ATTR_NAME("h323-setup-time"), RadiusAttr::CiscoVSA_h323_setup_time), 
	CiscoAttrName(CISCO_ATTR_NAME("h323-connect-time"), RadiusAttr::CiscoVSA_h323_connect_time),
	CiscoAttrName(CISCO_ATTR_NAME("h323-disconnect-time"), RadiusAttr::CiscoVSA_h323_disconnect_time),
	CiscoAttrName(CISCO_ATTR_NAME("h323-disconnect-cause"), RadiusAttr::CiscoVSA_h323_disconnect_cause),
	CiscoAttrName(CISCO_ATTR_NAME("h323-credit-amount"), RadiusAttr::CiscoVSA_h323_credit_amount), 
	CiscoAttrName(CISCO_ATTR_NAME("h323-credit-time"), RadiusAttr::CiscoVSA_h323_credit_time),
	CiscoAttrName(CISCO_ATTR_NAME("h323-return-code"), RadiusAttr::CiscoVSA_h323_return_code), 
	CiscoAttrName(CISCO_ATTR_NAME("h323-billing-model"), RadiusAttr::CiscoVSA_h323_billing_model), 
	CiscoAttrName(CISCO_ATTR_NAME("h323-currency"), RadiusAttr::CiscoVSA_h323_currency),
	CiscoAttrName(CISCO_ATTR_NAME("h323-redirect-number"), RadiusAttr::CiscoVSA_h323_redirect_number),
	CiscoAttrName(CISCO_ATTR_NAME("h323-redirect-ip-address"), RadiusAttr::CiscoVSA_h323_redirect_ip_address), 
	CiscoAttrName(CISCO_ATTR_NAME("h323-gw-id"), RadiusAttr::CiscoVSA_h323_gw_id),
	CiscoAttrName(CISCO_ATTR_NAME("h323-call-origin"), RadiusAttr::CiscoVSA_h323_call_origin),
	CiscoAttrName(CISCO_ATTR_NAME("h323-call-type"), RadiusAttr::CiscoVSA_h323_call_type), 
	CiscoAttrName(CISCO_ATTR_NAME("h323-voice-quality"), RadiusAttr::CiscoVSA_h323_voice_quality),
	CiscoAttrName(CISCO_ATTR_NAME("h323-incoming-conf-id"), RadiusAttr::CiscoVSA_h323_incoming_conf_id),
	CiscoAttrName(CISCO_ATTR_NAME("h323-preferred-lang"), RadiusAttr::CiscoVSA_h323_preferred_lang),
	CiscoAttrName(CISCO_ATTR_NAME("release-source"),RadiusAttr::CiscoVSA_release_source),
	CiscoAttrName(CISCO_ATTR_NAME("preferred-codec"),RadiusAttr::CiscoVSA_preferred_codec),
	CiscoAttrName(CISCO_ATTR_NAME("rewritten-e164-num"),RadiusAttr::CiscoVSA_rewritten_e164_num),
	CiscoAttrName(NULL, 0, 0)
};


/// macro to put an integer into the buffer using big endian byte order
inline
void SetRadiusInteger(
	unsigned char* intBuffer,
	unsigned intValue
	)
{
	intBuffer[0] = (BYTE)((intValue >> 24) & 0xff);
	intBuffer[1] = (BYTE)((intValue >> 16) & 0xff);
	intBuffer[2] = (BYTE)((intValue >> 8) & 0xff);
	intBuffer[3] = (BYTE)(intValue & 0xff);
}

/// macro to get an integer from the buffer stored in big endian byte order
inline
unsigned GetRadiusInteger(
	const unsigned char* intBuffer
	)
{
	return (((unsigned)intBuffer[0]) << 24) | (((unsigned)intBuffer[1]) << 16)
		| (((unsigned)intBuffer[2]) << 8) | ((unsigned)intBuffer[3]);
}

} // anonymous namespace


RadiusAttr::RadiusAttr() : m_type(0), m_length(0)
{
}

RadiusAttr::RadiusAttr( 
	unsigned char attrType, /// type of the attribute
	const void* attrValue, /// actual attribute value data
	PINDEX valueLength /// length for the attribute value
	) : m_type(attrType), m_length(FixedHeaderLength)
{
	if (valueLength > 0)
		PAssertNULL(attrValue);

#ifdef _DEBUG
	PAssert(valueLength <= MaxValueLength, PInvalidParameter);
#endif

	if (valueLength > MaxValueLength)
		valueLength = MaxValueLength;

	if (valueLength > 0) {
		m_length = m_length + (unsigned char)valueLength;
		if (attrValue != NULL)
			memcpy(m_value, attrValue, valueLength);
	}
}

RadiusAttr::RadiusAttr(
	const void* attrValue, /// buffer with data to be stored in the attribute Value
	PINDEX valueLength, /// data length (bytes)
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	) : m_type(VendorSpecific), m_length(VsaRfc2865FixedHeaderLength),
		m_vendorType(vendorType), m_vendorLength(2)
{
	SetRadiusInteger(m_vendorId, vendorId);
	
	if (valueLength > 0)
		PAssertNULL(attrValue);
	
#ifdef _DEBUG
	PAssert(valueLength <= VsaMaxRfc2865ValueLength, PInvalidParameter);
#endif

	if (valueLength > VsaMaxRfc2865ValueLength)
		valueLength = VsaMaxRfc2865ValueLength;
	
	if (valueLength > 0) {
		m_length = m_length + (unsigned char)valueLength;
		m_vendorLength = m_vendorLength + (unsigned char)valueLength;
		if (attrValue != NULL)
			memcpy(m_vendorValue, attrValue, valueLength);
	}
}

RadiusAttr::RadiusAttr( 
	unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
	const PString& stringValue /// string to be stored in the attribute Value data
	) : m_type(attrType), m_length(FixedHeaderLength)
{
	if (attrType == VendorSpecific)
		PAssertAlways(PInvalidParameter);

	PINDEX attrLength = stringValue.GetLength();
	
	if (attrLength > MaxValueLength)
		attrLength = MaxValueLength;

	if (attrLength > 0) {
		m_length = m_length + (unsigned char)attrLength;
		memcpy(m_value, (const char*)stringValue, attrLength);
	}
}

RadiusAttr::RadiusAttr( 
	unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
	int intValue /// 32 bit integer to be stored in the attribute Value
	) : m_type(attrType), m_length(FixedHeaderLength + 4)
{
	if (attrType == VendorSpecific)
		PAssertAlways(PInvalidParameter);

	SetRadiusInteger(m_value, intValue);
}

static unsigned _addrLen(const PIPSocket::Address & addr)
{
	return (addr.GetVersion() == 6) ? 16 : 4;
}

RadiusAttr::RadiusAttr( 
	unsigned char attrType, /// Attribute Type (see #enum AttrTypes#)
	const PIPSocket::Address & addressValue /// IP address to be stored in the attribute Value
	) : m_type(attrType), m_length(FixedHeaderLength + _addrLen(addressValue))
{
	if (attrType == VendorSpecific)
		PAssertAlways(PInvalidParameter);

	if (addressValue.GetVersion() == 6) {
		for (unsigned i=0; i < 15; i++)
			m_value[i] = addressValue[i];
	} else {
		const DWORD addr = (DWORD)addressValue;

		m_value[0] = ((const BYTE*)&addr)[0];
		m_value[1] = ((const BYTE*)&addr)[1];
		m_value[2] = ((const BYTE*)&addr)[2];
		m_value[3] = ((const BYTE*)&addr)[3];
	}
}

RadiusAttr::RadiusAttr( 
	const PString& stringValue, /// string to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	) : m_type(VendorSpecific), m_length(VsaRfc2865FixedHeaderLength),
		m_vendorType(vendorType), m_vendorLength(2)
{
	SetRadiusInteger(m_vendorId, vendorId);
	
	PINDEX vsaLength = stringValue.GetLength();

#ifdef _DEBUG	
	PAssert(vsaLength <= VsaMaxRfc2865ValueLength, PInvalidParameter);
#endif
	if (vsaLength > VsaMaxRfc2865ValueLength)
		vsaLength = VsaMaxRfc2865ValueLength;

	if (vsaLength > 0) {
		m_length = m_length + (unsigned char)vsaLength;
		m_vendorLength = m_vendorLength + (unsigned char)vsaLength;
		memcpy(m_vendorValue, (const char*)stringValue, vsaLength);
	}
}

RadiusAttr::RadiusAttr( 
	int intValue, /// 32 bit integer to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	) : m_type(VendorSpecific), m_length(VsaRfc2865FixedHeaderLength + 4),
		m_vendorType(vendorType), m_vendorLength(2 + 4)
{
	SetRadiusInteger(m_vendorId, vendorId);
	SetRadiusInteger(m_vendorValue, intValue);
}

RadiusAttr::RadiusAttr(
	const PIPSocket::Address& addressValue, /// IP address to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	) : m_type(VendorSpecific), m_length(VsaRfc2865FixedHeaderLength + _addrLen(addressValue)),
		m_vendorType(vendorType), m_vendorLength(2 + _addrLen(addressValue))
{
	SetRadiusInteger(m_vendorId, vendorId);
	
	if (addressValue.GetVersion() == 6) {
		for (unsigned i=0; i < 15; i++)
			m_vendorValue[i] = addressValue[i];
	} else {
		const DWORD addr = (DWORD)addressValue;
		m_vendorValue[0] = ((BYTE*)&addr)[0];
		m_vendorValue[1] = ((BYTE*)&addr)[1];
		m_vendorValue[2] = ((BYTE*)&addr)[2];
		m_vendorValue[3] = ((BYTE*)&addr)[3];
	}
}

RadiusAttr::RadiusAttr(
	unsigned char type, /// Cisco-specific attribute type
	bool vsaHack, /// true to not prepend attribute name to its value
	const PString& stringValue /// string to be stored in the attribute Value
	) : m_type(VendorSpecific), m_length(VsaRfc2865FixedHeaderLength),
		m_vendorType(type), m_vendorLength(2)
{
	SetRadiusInteger(m_vendorId, CiscoVendorId);
	if (!vsaHack) {
		int i = 0;
		while (CiscoAttrNames[i].m_name != NULL)
			if (CiscoAttrNames[i].m_type == type) {
				memcpy(m_vendorValue, CiscoAttrNames[i].m_name, CiscoAttrNames[i].m_nameLen);
				m_length = m_length + (unsigned char)CiscoAttrNames[i].m_nameLen;
				m_vendorLength = m_vendorLength + (unsigned char)CiscoAttrNames[i].m_nameLen;
				m_data[m_length++] = '=';
				m_vendorLength++;
				break;
			} else
				i++;
	}
	const PINDEX len = stringValue.GetLength();
	if (((PINDEX)m_length + len) > MaxLength)
		return;

	memcpy(m_data + (PINDEX)m_length, (const char*)stringValue, len);
	m_length = m_length + (unsigned char)len;
	m_vendorLength = m_vendorLength + (unsigned char)len;
}

RadiusAttr::RadiusAttr(
	const void* rawData, /// buffer with the attribute raw data
	PINDEX rawLength /// length (bytes) of the buffer
	) : m_type(0), m_length(0)
{
	Read(rawData, rawLength);
}

int RadiusAttr::GetVsaVendorId() const 
{
	return GetRadiusInteger(m_vendorId);
}

bool RadiusAttr::Write(
	PBYTEArray& buffer, /// buffer the attribute data will be written to
	PINDEX& written, /// number of bytes written (if successful return)
	PINDEX offset /// offset into the buffer, where writting starts
	) const
{
	if (!IsValid())
		return false;

	if (offset == P_MAX_INDEX)
		offset = buffer.GetSize();
		
	const PINDEX len = m_length;
	memcpy(buffer.GetPointer(offset + len) + offset, m_data, len);
	written = len;

	return true;
}

bool RadiusAttr::Read(const void* rawData, PINDEX rawLength)
{
	m_type = m_length = 0;

#ifdef _DEBUG	
	PAssertNULL(rawData);
	PAssert(rawLength >= FixedHeaderLength, PInvalidParameter);
#endif

	if (rawData == NULL || rawLength < FixedHeaderLength)
		return false;

	const PINDEX len = ((const unsigned char*)rawData)[1];
	if (len < FixedHeaderLength || len > rawLength
		|| (((const unsigned char*)rawData)[0] == VendorSpecific
			&& len < VsaFixedHeaderLength))
		return false;

	memcpy(m_data, rawData, len);
	return true;
}

void RadiusAttr::PrintOn(
	ostream &strm   /// Stream to print the object into.
    ) const
{
	const std::streamsize indent = strm.precision() + 2;

	if (!IsValid()) {
		strm << "(Invalid) {\n";
		if (m_length > 0) {
			const ios::fmtflags flags = strm.flags();
			const PBYTEArray value((const BYTE*)m_data, m_length, FALSE);

			strm << hex << setfill('0') << resetiosflags(ios::floatfield)
				<< setprecision(indent) << setw(16);

			if (value.GetSize() <= 32 || (flags&ios::floatfield) != ios::fixed)
				strm << value << '\n';
			else {
				const PBYTEArray truncatedArray((const BYTE*)value, 32, FALSE);
				strm << truncatedArray << '\n'
					<< setfill(' ') << setw(indent+4) << "...\n";
			}

			strm << dec << setfill(' ');
			strm.flags(flags);
		}
		strm << setw(indent) << "}\n" << setprecision(indent-2);
		return;
	}
	
	strm << "{\n";

	strm << setw(indent+7) << "type = " << (unsigned)m_type
		<< " (" << PMAP_ATTR_TYPE_TO_NAME(m_type) << ")\n";
	const PINDEX totalLen = m_length;
	
	strm << setw(indent+9) << "length = " << totalLen << " octets\n";
	
	if (!IsVsa()) {
		const ios::fmtflags flags = strm.flags();
		const PINDEX valueLen = (totalLen <= FixedHeaderLength) 
			? 0 : (totalLen - FixedHeaderLength);
		const PBYTEArray value((const BYTE*)m_value, valueLen, FALSE);

		strm << setw(indent+8) << "value = " << value.GetSize() << " octets {\n";
		strm << hex << setfill('0') << resetiosflags(ios::floatfield)
			<< setprecision(indent+2) << setw(16);

		if (value.GetSize() > 0) {
			if (value.GetSize() <= 32 || (flags&ios::floatfield) != ios::fixed)
				strm << value << '\n';
			else {
				const PBYTEArray truncatedArray((const BYTE*)value, 32, FALSE);
				strm << truncatedArray << '\n'
					<< setfill(' ') << setw(indent+6) << "...\n";
			}
		}

		strm << dec << setfill(' ') << setprecision(indent);
		strm.flags(flags);
		strm << setw(indent+2) << "}\n";
	} else {
		strm << setw(indent+11) << "vendorId = " 
			<< GetVsaVendorId() << '\n';

		const ios::fmtflags flags = strm.flags();
		PINDEX valueLen = (totalLen <= VsaFixedHeaderLength)
			? 0 : (totalLen - VsaFixedHeaderLength);
		PINDEX headerLen = VsaFixedHeaderLength;
		if (valueLen > 2) {
			valueLen -= 2;
			headerLen += 2;
			strm << setw(indent+13) << "vendorType = " 
				<< (unsigned)m_vendorType << '\n';
			strm << setw(indent+15) << "vendorLength = " 
				<< (unsigned)m_vendorLength << '\n';
		}
		
		const PBYTEArray value((const BYTE*)(m_data + headerLen), valueLen, FALSE);

		strm << setw(indent+14) << "vendorValue = " << value.GetSize() << " octets {\n";
		strm << hex << setfill('0') << resetiosflags(ios::floatfield)
			<< setprecision(indent+2) << setw(16);

		if (value.GetSize() > 0) {
			if (value.GetSize() <= 32 || (flags&ios::floatfield) != ios::fixed)
				strm << value << '\n';
			else {
				const PBYTEArray truncatedArray((const BYTE*)value, 32, FALSE);
				strm << truncatedArray << '\n'
					<< setfill(' ') << setw(indent+6) << "...\n";
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
	PINDEX len = m_length;
	len = (len <= VsaRfc2865FixedHeaderLength) 
		? 0 : (len - VsaRfc2865FixedHeaderLength);
	
	PINDEX len2 = 0;
	if (len > 0) {
		len2 = m_vendorLength;
		len2 = (len2 <= 2) ? 0 : (len2 - 2);
	}
	if (len2 < len)
		len = len2;
		
	return len;
}

bool RadiusAttr::GetValue(PBYTEArray& buffer, PINDEX offset) const
{
	if (!IsValid())
		return false;
		
	const PINDEX len = GetValueLength();

	if (offset == P_MAX_INDEX)
		offset = buffer.GetSize();
		
	if (len > 0)
		memcpy(buffer.GetPointer(offset + len) + offset,
			m_data + (IsVsa() ? VsaFixedHeaderLength : FixedHeaderLength), len
			);
		
	return true;
}

bool RadiusAttr::GetVsaValue(PBYTEArray& buffer, PINDEX offset) const
{
	if (!(IsValid() && IsVsa()))
		return false;
		
	const PINDEX len = GetVsaValueLength();

	if (offset == P_MAX_INDEX)
		offset = buffer.GetSize();
		
	if (len > 0)
		memcpy(buffer.GetPointer(len + offset) + offset, m_vendorValue, len);

	return true;
}

PString RadiusAttr::AsString() const
{
	if (!IsValid())
		return PString::Empty();

	const PINDEX len = m_length;
	const PINDEX headerLen = (m_type == VendorSpecific) 
			? VsaFixedHeaderLength : FixedHeaderLength;

	if (len <= headerLen)
		return PString::Empty();
	else
		return PString((const char*)(m_data + headerLen), len - headerLen);
}

int RadiusAttr::AsInteger() const
{
	if (m_length < (FixedHeaderLength+4) || m_type == VendorSpecific)
		return 0;
	
	return GetRadiusInteger(m_value);
}

PIPSocket::Address RadiusAttr::AsAddress() const
{
	if (m_length < (FixedHeaderLength+4) || m_type == VendorSpecific)
		return 0;

	if (m_length == (FixedHeaderLength+16)) {
		return PIPSocket::Address(16, (const BYTE*)m_value);
	} else {
		DWORD addr = 0;
		((BYTE*)&addr)[0] = m_value[0];
		((BYTE*)&addr)[1] = m_value[1];
		((BYTE*)&addr)[2] = m_value[2];
		((BYTE*)&addr)[3] = m_value[3];
		return addr;
	}
}

PString RadiusAttr::AsVsaString() const
{
	if (!IsValid() || m_type != VendorSpecific)
		return PString::Empty();
		
	const PINDEX len = m_length;

	if (len <= VsaRfc2865FixedHeaderLength)
		return PString::Empty();
	else
		return PString((const char*)m_vendorValue, len - VsaRfc2865FixedHeaderLength);
}

PString RadiusAttr::AsCiscoString() const
{
	if (!IsValid() || m_type != VendorSpecific 
			|| GetRadiusInteger(m_vendorId) != CiscoVendorId)
		return PString::Empty();
		
	const PINDEX len = m_length;
	PINDEX offset = VsaRfc2865FixedHeaderLength;

	int i = 0;
	while (CiscoAttrNames[i].m_name != NULL)
		if (CiscoAttrNames[i].m_type == m_vendorType) {
			if (CiscoAttrNames[i].m_nameLen < (size_t)(len - offset))
				if (memcmp(m_data + offset, CiscoAttrNames[i].m_name,
						CiscoAttrNames[i].m_nameLen) == 0
						&& m_data[offset + CiscoAttrNames[i].m_nameLen] == '=')
					offset += CiscoAttrNames[i].m_nameLen + 1;
			break;
		} else
			i++;
			
	if (offset >= len)
		return PString::Empty();
	else	
		return PString((const char*)m_data + offset, len - offset);
}

int RadiusAttr::AsVsaInteger() const
{
	if (m_length < (VsaRfc2865FixedHeaderLength+4) || m_type != VendorSpecific)
		return 0;
		
	return GetRadiusInteger(m_vendorValue);
}

PIPSocket::Address RadiusAttr::AsVsaAddress() const
{
	if (m_length < (VsaRfc2865FixedHeaderLength+4) || m_type != VendorSpecific)
		return 0;
	
	if (m_length == (VsaRfc2865FixedHeaderLength + 16)) {
		return PIPSocket::Address(16, (const BYTE*)m_vendorValue);
	} else {
		DWORD addr = 0;
		((BYTE*)&addr)[0] = m_vendorValue[0];
		((BYTE*)&addr)[1] = m_vendorValue[1];
		((BYTE*)&addr)[2] = m_vendorValue[2];
		((BYTE*)&addr)[3] = m_vendorValue[3];
		return addr;
	}
}


RadiusPDU::RadiusPDU() : m_code(Invalid), m_id(0)
{
	SetLength(FixedHeaderLength);
}

RadiusPDU::RadiusPDU(const RadiusPDU & pdu)
{
	CopyContents(pdu);
}

RadiusPDU::RadiusPDU( 
	unsigned char packetCode, /// code - see #Codes enum#
	unsigned char packetId /// packet id (sequence number)
	) : m_code(packetCode), m_id(packetId)
{
	SetLength(FixedHeaderLength);
}

RadiusPDU::RadiusPDU(
	const void * rawData, /// raw data buffer
	PINDEX rawLength /// raw data length
	)
{
	if (!Read(rawData, rawLength)) {
		m_code = m_id = Invalid;
		SetLength(FixedHeaderLength);
	}
}

void RadiusPDU::PrintOn( 
	ostream& strm /// Stream to print the object into.
	) const
{
	const std::streamsize indent = strm.precision() + 2;

	strm << ((!IsValid()) ? "(Invalid) {\n" : "{\n");

	strm << setw(indent+7) << "code = " << (unsigned)m_code
		<< " (" << PMAP_CODE_TO_NAME(m_code) << ")\n";
	strm << setw(indent+5) << "id = " << (unsigned)m_id << '\n';
	strm << setw(indent+9) << "length = " << GetLength() << " octets\n";

	const ios::fmtflags flags = strm.flags();
	const PBYTEArray value((const BYTE*)m_authenticator, AuthenticatorLength, FALSE);

	strm << setw(indent+28) << "authenticator = 16 octets {\n";
	strm << hex << setfill('0') << resetiosflags(ios::floatfield)
		<< setprecision(indent+2) << setw(16);
	strm << value << '\n';
	strm << dec << setfill(' ') << setprecision(indent);
	strm.flags(flags);
	strm << setw(indent+2) << "}\n";

	const PINDEX numAttributes = GetNumAttributes();
	if (numAttributes == 0)
		strm << setw(indent+22) << "attributes = <<null>>\n";
	else {
		strm << setw(indent+13) << "attributes = " << numAttributes << " elements {\n";

		const std::streamsize aindent = indent + 2;

		const RadiusAttr* attr = GetAttr();
		PINDEX i = 0;
		while (attr != NULL) {
			strm << setw(aindent + 1) << "[" << i << "]= " 
				<< setprecision(aindent) << *attr << setprecision(indent);
			attr = GetAttr(attr);
			i++;
		}
		strm << setw(aindent) << "}\n";
	}

	strm << setw(indent-1) << "}\n" << setprecision(indent-2);
}

bool RadiusPDU::IsValid() const
{
	if (m_code == Invalid)
		return false;

	const PINDEX len = GetLength();
	if (len < MinPduLength || len > MaxPduLength)
		return false;
	
	PINDEX currLen = FixedHeaderLength;
	while (currLen < len) {
		const RadiusAttr* const attr 
			= reinterpret_cast<const RadiusAttr*>(m_data + currLen);
		const PINDEX remainingLen = len - currLen;
		if (remainingLen < RadiusAttr::FixedHeaderLength 
			|| remainingLen < attr->GetLength() || !attr->IsValid())
			break;
		currLen += attr->GetLength();	 
	}
	
	return currLen == len;
}

void RadiusPDU::GetAuthenticator(PBYTEArray & vector, PINDEX offset) const
{
	if (offset == P_MAX_INDEX)
		offset = vector.GetSize();
	memcpy(vector.GetPointer(offset + AuthenticatorLength) + offset,
		m_authenticator, AuthenticatorLength
		);
}

bool RadiusPDU::SetAuthenticator(const PBYTEArray & vector, PINDEX offset)
{
	PINDEX len = vector.GetSize();
	if (offset >= len)
		return false;

	len -= offset;

	if (len > 0)
		memcpy(m_authenticator, ((const BYTE*)vector)+offset,
			(len < AuthenticatorLength) ? len : AuthenticatorLength
			);

	return true;
}

bool RadiusPDU::SetAuthenticator(const void * data)
{
#ifdef _DEBUG
	PAssertNULL(data);
#endif
	if (data == NULL)
		return false;

	memcpy(m_authenticator, data, AuthenticatorLength);
	return true;
}

void RadiusPDU::SetAuthenticator(PRandom & random)
{
	DWORD r = (DWORD)random;
	m_authenticator[0] = ((const BYTE*)&r)[0];
	m_authenticator[1] = ((const BYTE*)&r)[1];
	m_authenticator[2] = ((const BYTE*)&r)[2];
	m_authenticator[3] = ((const BYTE*)&r)[3];
	r = (DWORD)random;
	m_authenticator[4] = ((const BYTE*)&r)[0];
	m_authenticator[5] = ((const BYTE*)&r)[1];
	m_authenticator[6] = ((const BYTE*)&r)[2];
	m_authenticator[7] = ((const BYTE*)&r)[3];
	r = (DWORD)random;
	m_authenticator[8] = ((const BYTE*)&r)[0];
	m_authenticator[9] = ((const BYTE*)&r)[1];
	m_authenticator[10] = ((const BYTE*)&r)[2];
	m_authenticator[11] = ((const BYTE*)&r)[3];
	r = (DWORD)random;
	m_authenticator[12] = ((const BYTE*)&r)[0];
	m_authenticator[13] = ((const BYTE*)&r)[1];
	m_authenticator[14] = ((const BYTE*)&r)[2];
	m_authenticator[15] = ((const BYTE*)&r)[3];
}

void RadiusPDU::SetAuthenticator( 
	const PString & secret,
	PMessageDigest5 & md5 
	)
{
	if (m_code == AccountingRequest) {
		const PINDEX pduLength = GetLength();
		const PINDEX secretLength = secret.GetLength();
		
		memset(m_authenticator, 0, AuthenticatorLength);

		md5.Start();
		md5.Process(m_data, pduLength);
		if (secretLength > 0)
			md5.Process((const char*)secret, secretLength);
			
		PMessageDigest::Result digest;
		md5.CompleteDigest(digest);
		memcpy(m_authenticator, digest.GetPointer(), AuthenticatorLength);
	} else {
		PRandom random;
		SetAuthenticator(random);
	}
}

bool RadiusPDU::AppendAttr( 
	const RadiusAttr & attr /// attribute to be appended
	)
{
	const PINDEX len = GetLength();
	const PINDEX attrLen = attr.GetLength();
	if (!attr.IsValid() || (len + attrLen) > MaxPduLength)
		return false;
		
	*reinterpret_cast<RadiusAttr*>(m_data + len) = attr;
	
	SetLength(len + attrLen);
	return true;
}

bool RadiusPDU::AppendAttr( 
	unsigned char attrType, /// Attribute Type
	const void* attrValue, /// buffer with attribute Value data
	PINDEX valueLength /// length of attribute Value data
	)
{
	const PINDEX len = GetLength();
	const PINDEX attrLen = RadiusAttr::FixedHeaderLength + valueLength;
	if (attrLen > RadiusAttr::MaxLength || (len + attrLen) > MaxPduLength)
		return false;
		
	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = attrType;
	attr->m_length = attrLen;
	memcpy(attr->m_value, attrValue, valueLength);
	SetLength(len + attrLen);
	
	return true;
}

bool RadiusPDU::AppendAttr( 
	unsigned char attrType, /// Attribute Type
	const PString& stringValue /// string to be stored in the attribute Value data
	)
{
	const PINDEX len = GetLength();
	const PINDEX attrLen = RadiusAttr::FixedHeaderLength + stringValue.GetLength();
	if (attrLen > RadiusAttr::MaxLength || (len + attrLen) > MaxPduLength)
		return false;
		
	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = attrType;
	attr->m_length = attrLen;
	memcpy(attr->m_value, (const char*)stringValue, stringValue.GetLength());
	SetLength(len + attrLen);
	
	return true;
}

bool RadiusPDU::AppendAttr( 
	unsigned char attrType, /// Attribute Type
	int intValue /// 32 bit integer to be stored in the attribute Value
	)
{
	const PINDEX len = GetLength();
	const PINDEX attrLen = RadiusAttr::FixedHeaderLength + 4;
	if (attrLen > RadiusAttr::MaxLength || (len + attrLen) > MaxPduLength)
		return false;
		
	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = attrType;
	attr->m_length = attrLen;
	SetRadiusInteger(attr->m_value, intValue);
	SetLength(len + attrLen);
	
	return true;
}

bool RadiusPDU::AppendAttr( 
	unsigned char attrType, /// Attribute Type
	const PIPSocket::Address & addressValue /// IP address to be stored in the attribute Value
	)
{
	const PINDEX len = GetLength();
	const PINDEX attrLen = RadiusAttr::FixedHeaderLength + _addrLen(addressValue);
	if (attrLen > RadiusAttr::MaxLength || (len + attrLen) > MaxPduLength)
		return false;

	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = attrType;
	attr->m_length = attrLen;
	if (addressValue.GetVersion() == 6) {
		for (unsigned i=0; i < 15; i++)
			attr->m_value[i] = addressValue[i];
	} else {
		const DWORD addr = (DWORD)addressValue;
		attr->m_value[0] = ((const BYTE*)&addr)[0];
		attr->m_value[1] = ((const BYTE*)&addr)[1];
		attr->m_value[2] = ((const BYTE*)&addr)[2];
		attr->m_value[3] = ((const BYTE*)&addr)[3];
	}
	SetLength(len + attrLen);
	
	return true;
}

bool RadiusPDU::AppendVsaAttr( 
	const void* attrValue, /// buffer with data to be stored in the attribute Value
	PINDEX valueLength, /// data length (bytes)
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	)
{
	const PINDEX len = GetLength();
	const PINDEX attrLen = RadiusAttr::VsaRfc2865FixedHeaderLength + valueLength;
	if (attrLen > RadiusAttr::MaxLength || (len + attrLen) > MaxPduLength)
		return false;
		
	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = RadiusAttr::VendorSpecific;
	attr->m_length = attrLen;
	SetRadiusInteger(attr->m_vendorId, vendorId);
	attr->m_vendorType = vendorType;
	attr->m_vendorLength = valueLength + 2;
	memcpy(attr->m_vendorValue, attrValue, valueLength);
	SetLength(len + attrLen);
	
	return true;
}

bool RadiusPDU::AppendVsaAttr( 
	const PString& stringValue, /// string to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	)
{
	const PINDEX len = GetLength();
	const PINDEX valueLen = stringValue.GetLength();
	const PINDEX attrLen = RadiusAttr::VsaRfc2865FixedHeaderLength + valueLen;
	if (attrLen > RadiusAttr::MaxLength || (len + attrLen) > MaxPduLength)
		return false;
		
	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = RadiusAttr::VendorSpecific;
	attr->m_length = attrLen;
	SetRadiusInteger(attr->m_vendorId, vendorId);
	attr->m_vendorType = vendorType;
	attr->m_vendorLength = valueLen + 2;
	memcpy(attr->m_vendorValue, (const char*)stringValue, valueLen);
	SetLength(len + attrLen);
	
	return true;
}

bool RadiusPDU::AppendVsaAttr( 
	int intValue, /// 32 bit integer to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	)
{
	const PINDEX len = GetLength();
	const PINDEX attrLen = RadiusAttr::VsaRfc2865FixedHeaderLength + 4;
	if (attrLen > RadiusAttr::MaxLength || (len + attrLen) > MaxPduLength)
		return false;
		
	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = RadiusAttr::VendorSpecific;
	attr->m_length = attrLen;
	SetRadiusInteger(attr->m_vendorId, vendorId);
	attr->m_vendorType = vendorType;
	attr->m_vendorLength = 4 + 2;
	SetRadiusInteger(attr->m_vendorValue, intValue);
	SetLength(len + attrLen);
	
	return true;
}

bool RadiusPDU::AppendVsaAttr( 
	const PIPSocket::Address& addressValue, /// IP address to be stored in the attribute Value
	int vendorId, /// 32 bit vendor identifier
	unsigned char vendorType /// vendor-specific attribute type
	)
{
	const PINDEX len = GetLength();
	const PINDEX attrLen = RadiusAttr::VsaRfc2865FixedHeaderLength + _addrLen(addressValue);
	if (attrLen > RadiusAttr::MaxLength || (len + attrLen) > MaxPduLength)
		return false;

	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = RadiusAttr::VendorSpecific;
	attr->m_length = attrLen;
	SetRadiusInteger(attr->m_vendorId, vendorId);
	attr->m_vendorType = vendorType;
	attr->m_vendorLength = _addrLen(addressValue) + 2;
	if (addressValue.GetVersion() == 6) {
		for (unsigned i=0; i < 15; i++)
			attr->m_vendorValue[i] = addressValue[i];
	} else {
		const DWORD addr = (DWORD)addressValue;
		attr->m_vendorValue[0] = ((const BYTE*)&addr)[0];
		attr->m_vendorValue[1] = ((const BYTE*)&addr)[1];
		attr->m_vendorValue[2] = ((const BYTE*)&addr)[2];
		attr->m_vendorValue[3] = ((const BYTE*)&addr)[3];
	}
	SetLength(len + attrLen);
	
	return true;
}

/// Append a string Cisco VSA attribute
bool RadiusPDU::AppendCiscoAttr( 
	unsigned char vendorType, /// vendor-specific attribute type
	const PString& stringValue, /// string to be stored in the attribute Value
	bool vsaHack /// true to not prepend attribute name to its value
	)
{
	const PINDEX len = GetLength();
	PINDEX attrLen = RadiusAttr::VsaRfc2865FixedHeaderLength;
	if ((len + attrLen) > MaxPduLength)
		return false;
		
	RadiusAttr* const attr = reinterpret_cast<RadiusAttr*>(m_data + len);
	attr->m_type = RadiusAttr::VendorSpecific;
	attr->m_length = attrLen;
	SetRadiusInteger(attr->m_vendorId, RadiusAttr::CiscoVendorId);
	attr->m_vendorType = vendorType;
	attr->m_vendorLength = 2;

	if (!vsaHack) {
		int i = 0;
		while (CiscoAttrNames[i].m_name != NULL)
			if (CiscoAttrNames[i].m_type == vendorType) {
				attrLen += CiscoAttrNames[i].m_nameLen + 1;
				if ((len + attrLen) > MaxPduLength)
					return false;
				memcpy(attr->m_vendorValue, CiscoAttrNames[i].m_name, CiscoAttrNames[i].m_nameLen);
				attr->m_length = attr->m_length 
					+ (unsigned char)CiscoAttrNames[i].m_nameLen;
				attr->m_vendorLength = attr->m_vendorLength 
					+ (unsigned char)CiscoAttrNames[i].m_nameLen;
				attr->m_data[attr->m_length++] = '=';
				attr->m_vendorLength++;
				break;
			} else
				i++;
	}
	const PINDEX strLen = stringValue.GetLength();
	attrLen += strLen;
	if (((PINDEX)attr->m_length + strLen) > RadiusAttr::MaxLength
		|| (len + attrLen) > MaxPduLength)
		return false;

	memcpy(attr->m_data + (PINDEX)attr->m_length, (const char*)stringValue, strLen);
	attr->m_length = attr->m_length + (unsigned char)strLen;
	attr->m_vendorLength = attr->m_vendorLength + (unsigned char)strLen;

	SetLength(len + attrLen);
	return true;
}

PINDEX RadiusPDU::GetNumAttributes() const
{
	PINDEX count = 0;
	const RadiusAttr* attr = GetAttr();
	while (attr != NULL) {
		attr = GetAttr(attr);
		count++;
	}
	return count;
}

const RadiusAttr* RadiusPDU::GetAttr(const RadiusAttr * prevAttr) const
{
	const PINDEX len = GetLength();
	PINDEX offset = FixedHeaderLength;
	if (prevAttr != NULL) {
		const unsigned long ptr = reinterpret_cast<unsigned long>(prevAttr);
#ifdef _DEBUG
		PAssert(ptr >= reinterpret_cast<unsigned long>(m_data + FixedHeaderLength)
			&& ptr < reinterpret_cast<unsigned long>(m_data + len), PInvalidParameter
			);
#endif
		offset = ptr - reinterpret_cast<unsigned long>(m_data) 
			+ prevAttr->GetLength();
	}

	return (offset >= len) 
		? NULL : reinterpret_cast<const RadiusAttr*>(m_data + offset);
}

const RadiusAttr* RadiusPDU::FindAttr(
	unsigned char attrType, /// attribute type to be matched
	const RadiusAttr* prevAttr /// start element for the search operation
	) const
{
	const RadiusAttr* attr = GetAttr(prevAttr);
	while (attr != NULL && attr->GetType() != attrType)
		attr = GetAttr(attr);
	return attr;
}
		
const RadiusAttr* RadiusPDU::FindVsaAttr(
	int vendorId, /// vendor identifier to be matched
	unsigned char vendorType, /// vendor attribute type to be matched
	const RadiusAttr* prevAttr /// start element for the search operation
	) const
{
	const RadiusAttr* attr = GetAttr(prevAttr);
	while (attr != NULL && (!attr->IsVsa() 
		|| attr->GetVsaVendorId() != vendorId || attr->GetVsaType() != vendorType))
		attr = GetAttr(attr);
	return attr;
}

bool RadiusPDU::Write(PBYTEArray& buffer, PINDEX& written, PINDEX offset) const
{
	if (!IsValid())
		return false;

	if (offset == P_MAX_INDEX)
		offset = buffer.GetSize();
		
	const PINDEX len = GetLength();
	BYTE* const buffptr = buffer.GetPointer(len + offset) + offset;
	
	memcpy(buffptr, m_data, len);
	written = len;
	
	return true;
}

bool RadiusPDU::Read(const void* rawData, PINDEX rawLength)
{
#ifdef _DEBUG
	PAssertNULL(rawData);
	PAssert(rawLength >= MinPduLength, PInvalidParameter);
#endif

	m_code = m_id = Invalid;
	SetLength(FixedHeaderLength);

	if (rawData == NULL || rawLength < MinPduLength)
		return false;

	const BYTE* buffptr = (const BYTE*)rawData;

	memcpy(m_data, buffptr, FixedHeaderLength);
	buffptr += FixedHeaderLength;

	const PINDEX length = GetLength();
	if (length > rawLength || length < MinPduLength || length > MaxPduLength) {
		m_code = m_id = Invalid;
		SetLength(FixedHeaderLength);
		return false;
	}

	if (length > FixedHeaderLength) {
		memcpy(m_attributes, buffptr, length - FixedHeaderLength);
	}

	return true;
}

bool RadiusPDU::Read(
		const PBYTEArray& buffer, /// buffer with RADIUS packet data
		PINDEX offset /// offset into the buffer, where data starts
		)
{
	const PINDEX len = buffer.GetSize();

	if (len <= offset)
		return false;

	return Read(((const BYTE*)buffer) + offset, len - offset);
}

void RadiusPDU::CopyContents(const RadiusPDU& pdu)
{
	memcpy(m_data, pdu.m_data, FixedHeaderLength);

	const PINDEX len = GetLength();
	if (len < MinPduLength || len > MaxPduLength) {
		m_code = m_id = Invalid;
		SetLength(FixedHeaderLength);
		return;
	}

	if (len > FixedHeaderLength)
		memcpy(m_attributes, pdu.m_attributes, len - FixedHeaderLength);
}

bool RadiusPDU::EncryptPasswords( 
	const PString & secret,
	PMessageDigest5 & md5 
	)
{
	RadiusAttr* const pwdAttr = const_cast<RadiusAttr*>(FindAttr(RadiusAttr::UserPassword));
	if (pwdAttr == NULL)
		return true;

	/// generate 128-bit digest from shared secret and authenticator		
	PMessageDigest::Result digest;
	const PINDEX secretLength = secret.GetLength();

	md5.Start();
	if (secretLength > 0)
		md5.Process((const char*)secret, secretLength);
	md5.Process(m_authenticator, AuthenticatorLength);
	md5.CompleteDigest(digest);

	// calculate length of the new and the old User-Password value	
	const PINDEX origPwdLength = pwdAttr->GetValueLength();
	PINDEX encPwdLength = (origPwdLength == 0) 
		? 16 : ((origPwdLength + 15) & (~((PINDEX)0xf)));

	const PINDEX len = GetLength();
	if ((len + encPwdLength + RadiusAttr::FixedHeaderLength) > MaxPduLength)
		return false;

	// the encrypted password attribute will be appended as the last attribute
	RadiusAttr* const encPwdAttr = reinterpret_cast<RadiusAttr*>(m_data + len);
	encPwdAttr->m_type = RadiusAttr::UserPassword;
	encPwdAttr->m_length = encPwdLength + RadiusAttr::FixedHeaderLength;
	memset(encPwdAttr->m_value, 0, encPwdLength);
	if (origPwdLength > 0)
		memcpy(encPwdAttr->m_value, pwdAttr->m_value, origPwdLength);

	// encrypt first 16 bytes of the password
	DWORD* buf1ptr = reinterpret_cast<DWORD*>(encPwdAttr->m_value);
	const DWORD* buf2ptr = reinterpret_cast<const DWORD*>(digest.GetPointer());

	// XOR either byte-wise or dword-wise (if the memory block is aligned properly)
	if ((reinterpret_cast<unsigned long>(buf2ptr) & 3) 
		|| (reinterpret_cast<unsigned long>(buf1ptr) & 3)) {
		for (int _i = 0; _i < 16; _i++)
			((BYTE*)buf1ptr)[_i] = ((BYTE*)buf1ptr)[_i] ^ ((const BYTE*)buf2ptr)[_i];
		buf1ptr += 4;
		buf2ptr += 4;
	} else {
		// dword aligned data
		*buf1ptr = *buf1ptr ^ *buf2ptr++;
		++buf1ptr;
		*buf1ptr = *buf1ptr ^ *buf2ptr++;
		++buf1ptr;
		*buf1ptr = *buf1ptr ^ *buf2ptr++;
		++buf1ptr;
		*buf1ptr = *buf1ptr ^ *buf2ptr++;
		++buf1ptr;
	}

	// encrypt remaining 16 byte blocks of the password
	while (encPwdLength > 16) {
		encPwdLength -= 16;

		// get a new 128-bit digest for encryption
		md5.Start();
		if (secretLength > 0)
			md5.Process((const char*)secret, secretLength);
		md5.Process(buf1ptr - 4, 16);
		md5.CompleteDigest(digest);

		buf2ptr = reinterpret_cast<const DWORD*>(digest.GetPointer());
		if ((reinterpret_cast<unsigned long>(buf2ptr) & 3) 
			|| (reinterpret_cast<unsigned long>(buf1ptr) & 3)) {
			for (int _i = 0; _i < 16; _i++)
				((BYTE*)buf1ptr)[_i] = ((BYTE*)buf1ptr)[_i] ^ ((const BYTE*)buf2ptr)[_i];
			buf1ptr += 4;
			buf2ptr += 4;
		} else {
			// dword aligned data
			*buf1ptr = *buf1ptr ^ *buf2ptr++;
			++buf1ptr;
			*buf1ptr = *buf1ptr ^ *buf2ptr++;
			++buf1ptr;
			*buf1ptr = *buf1ptr ^ *buf2ptr++;
			++buf1ptr;
			*buf1ptr = *buf1ptr ^ *buf2ptr++;
			++buf1ptr;
		}
	}
	
	// delete the old (clear text) User-Password attribute and append the new
	// one (encrypted) at the end
	// this is done by overwritting the old User-Password with attributes 
	// present after it (memory block holding remaining attributes is moved)
	SetLength(len + encPwdAttr->GetLength() - pwdAttr->GetLength());
	memcpy(pwdAttr, 
		reinterpret_cast<unsigned char*>(pwdAttr) + pwdAttr->GetLength(),
		reinterpret_cast<unsigned long>(encPwdAttr) 
			- reinterpret_cast<unsigned long>(pwdAttr) + encPwdAttr->GetLength()
			- pwdAttr->GetLength()
		);
	// !!! At this point pwdAttr and encPwdAttr are no longer valid!
	
	return true;
}


#ifndef DEFAULT_PERMANENT_SYNCPOINTS
#define DEFAULT_PERMANENT_SYNCPOINTS 8
#endif

RadiusSocket::RadiusSocket(
	WORD _port
	) : m_permanentSyncPoints(DEFAULT_PERMANENT_SYNCPOINTS),
	m_isReading(false), m_nestedCount(0),
	m_idCacheTimeout(RadiusClient::DefaultIdCacheTimeout)
{
	if (!Listen(GNUGK_INADDR_ANY, 0, _port)) {
		PTRACE(1, "RADIUS\tCould not bind socket to the port " << _port
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": " 
			<< GetErrorText(PSocket::LastGeneralError)
			);
		Close();
	}
	m_addr = GNUGK_INADDR_ANY;
	m_port = _port;
	Toolkit::Instance()->PortNotification(RadiusPort, PortOpen, "udp", GNUGK_INADDR_ANY, _port);

	PRandom random;
	const unsigned _id_ = random;
	m_oldestId = m_nextId = (BYTE)(_id_^(_id_>>8)^(_id_>>16)^(_id_>>24));

	memset(m_readSyncPoints, 0, sizeof(m_readSyncPoints));
		
	if (IsOpen()) {
		memset(m_pendingRequests, 0, sizeof(m_pendingRequests));
		memset(m_syncPointMap, 0, sizeof(m_syncPointMap));
		memset(m_idTimestamps, 0, sizeof(m_idTimestamps));

		for (int i = 0; i < 256; i++)
			m_readSyncPointIndices[i] = P_MAX_INDEX;

		for (int i = 0; i < m_permanentSyncPoints; i++)
			m_readSyncPoints[i] = new PSyncPoint();
	}
}

RadiusSocket::RadiusSocket(
	const PIPSocket::Address & addr,
	WORD _port
	) : m_permanentSyncPoints(DEFAULT_PERMANENT_SYNCPOINTS),
	m_isReading(false), m_nestedCount(0),
	m_idCacheTimeout(RadiusClient::DefaultIdCacheTimeout)
{
	if (!Listen(addr, 0, _port)) {
		PTRACE(1, "RADIUS\tCould not bind socket to " << AsString(addr, _port)
			<< " - error " << GetErrorCode(PSocket::LastGeneralError) << '/'
			<< GetErrorNumber(PSocket::LastGeneralError) << ": " 
			<< GetErrorText(PSocket::LastGeneralError)
			);
		Close();
	}
	m_addr = addr;
	m_port = _port;
	Toolkit::Instance()->PortNotification(RadiusPort, PortOpen, "udp", addr, _port);

	PRandom random;
	const unsigned _id_ = random;
	m_oldestId = m_nextId = (BYTE)(_id_^(_id_>>8)^(_id_>>16)^(_id_>>24));

	memset(m_readSyncPoints, 0, sizeof(m_readSyncPoints));

	if (IsOpen()) {
		memset(m_pendingRequests, 0, sizeof(m_pendingRequests));
		memset(m_syncPointMap, 0, sizeof(m_syncPointMap));
		memset(m_idTimestamps, 0, sizeof(m_idTimestamps));

		int i;
		for (i = 0; i < 256; i++)
			m_readSyncPointIndices[i] = P_MAX_INDEX;

		for (i = 0; i < m_permanentSyncPoints; i++)
			m_readSyncPoints[i] = new PSyncPoint();
	}
}

RadiusSocket::~RadiusSocket()
{
	Toolkit::Instance()->PortNotification(RadiusPort, PortClose, "udp", m_addr, m_port);

	PWaitAndSignal lock(m_readMutex);

	for (int i = 0; i < 256; i++)
		delete m_readSyncPoints[i];
}

void RadiusSocket::PrintOn(ostream& strm) const
{
	strm << "port:" << GetPort()
		<< "[active requests: " << m_nestedCount << ", ID space: " 
		<< (PINDEX)m_oldestId << '-' << (PINDEX)m_nextId << ']';
}

PINDEX RadiusSocket::AllocReadSyncPoint()
{
	PINDEX idx = 0;

	for (PINDEX k = 0; k < 8; k++)
		if (m_syncPointMap[k] != 0xffffffff) {
			for (PINDEX i = 0, j = 1; i < 32; i++, j <<= 1, idx++)
				if ((m_syncPointMap[k] & ((DWORD)j)) == 0) {
					m_syncPointMap[k] |= (DWORD)j;
					if (m_readSyncPoints[idx] == NULL)
						m_readSyncPoints[idx] = new PSyncPoint();
					return idx;
				}
		} else
			idx += 32;

	return P_MAX_INDEX;
}

void RadiusSocket::FreeReadSyncPoint(PINDEX syncPointIndex)
{
	if (syncPointIndex < 256 && syncPointIndex >= 0) {
		m_syncPointMap[(syncPointIndex >> 5) & 7]
			&= ~(DWORD)(((DWORD)1)<<(syncPointIndex & 31));
		if (syncPointIndex >= m_permanentSyncPoints) {
			delete m_readSyncPoints[syncPointIndex];
			m_readSyncPoints[syncPointIndex] = NULL;
		}
	}
}

bool RadiusSocket::MakeRequest(
	const RadiusPDU* request,
	const Address& serverAddress,
	WORD serverPort,
	RadiusPDU*& pdu
	)
{
	if (!IsOpen() || request == NULL || !request->IsValid())
		return false;

	const PINDEX length = request->GetLength();
	const unsigned char id = request->GetId();
	const PTimeInterval timeout = GetReadTimeout();
	const PTime startTime;
	bool shouldRead = false;
	PSyncPoint* syncPoint = NULL;
	RadiusRequest* requestInfo = NULL;

	{
		if (!m_readMutex.Wait(timeout)) {
			PTRACE(4, "RADIUS\tMutex timed out for the request (id:" << (PINDEX)id << ')');
			return false;
		}

		PWaitAndSignal lock(m_readMutex, FALSE);

		if (m_pendingRequests[id] != NULL) {
			PTRACE(1, "RADIUS\tDuplicate RADIUS socket request (id:" << (PINDEX)id << ')');
			return false;
		}

		if (!m_isReading)
			m_isReading = shouldRead = true;
		else {
			const PINDEX index = AllocReadSyncPoint();
			if (index == P_MAX_INDEX) {
				PTRACE(1, "RADIUS\tFailed to allocate a new mutex for the request (id:" << (PINDEX)id << ')');
				return false;
			}
			syncPoint = m_readSyncPoints[index];
			if (syncPoint == NULL) {
				PTRACE(1, "RADIUS\tFailed to allocate a new mutex for the request (id:" << (PINDEX)id << ')');
				FreeReadSyncPoint(index);
				return false;
			}
			m_readSyncPointIndices[id] = index;
			m_nestedCount++;
		}
	
		requestInfo = m_pendingRequests[id] 
			= new RadiusRequest(request, pdu, &serverAddress, serverPort);
	}

	m_writeMutex.Wait();
	bool result = WriteTo(request, length, serverAddress, serverPort);
	if (!result) {
		PTRACE(5, "RADIUS\tError sending UDP packet ("
			<< GetErrorCode(LastWriteError) << '/'
			<< GetErrorNumber(LastWriteError) << ": "
			<< GetErrorText(LastWriteError) << " (id:" << (PINDEX)id << ')');
	}
	m_writeMutex.Signal();

	if (result)
	do {
		result = FALSE;

		if (shouldRead) {
			PIPSocket::Address remoteAddress;
			WORD remotePort;

			RadiusPDU* response = new RadiusPDU();
			result = ReadFrom(response, sizeof(RadiusPDU), remoteAddress, remotePort);
			if (!result) {
				if (GetErrorCode(LastReadError) == Timeout)
					PTRACE(6, "RADIUS\tTimed out reading socket " << *this);
				else
					PTRACE(5, "RADIUS\tError reading socket " << *this
						<< " (" << GetErrorCode(LastReadError) << '/'
						<< GetErrorNumber(LastReadError) << ": "
						<< GetErrorText(LastReadError) << ')');
				delete response;
				response = NULL;
				break;
			}

			result = FALSE;

			PINDEX bytesRead = GetLastReadCount();

			if (bytesRead < RadiusPDU::MinPduLength) {
				PTRACE(5, "RADIUS\tReceived packet is too small ("<< bytesRead << ')');
				delete response;
				response = NULL;
				continue;
			}

			if (!response->IsValid()) {
				PTRACE(5, "RADIUS\tReceived packet is not a valid Radius PDU");
				delete response;
				response = NULL;
				continue;
			}

			const BYTE newId = response->GetId();

			if (!m_readMutex.Wait(timeout)) {
				PTRACE(5, "RADIUS\tTimed out (mutex) - dropping PDU (id:" << (PINDEX)newId);
				delete response;
				response = NULL;
				continue;
			}

			PWaitAndSignal lock(m_readMutex, FALSE);

			if (m_pendingRequests[newId] == NULL) {
				PTRACE(5, "RADIUS\tUnmatched PDU received (code:"
					<< (PINDEX)response->GetCode() << ",id:"
					<< (PINDEX)newId << ')'
					);
				delete response;
				response = NULL;
				continue;
			}

			if (remoteAddress != *(m_pendingRequests[newId]->m_addr) 
				|| remotePort != m_pendingRequests[newId]->m_port) {
				PTRACE(5, "RADIUS\tReceived PDU from unknown address: " << AsString(remoteAddress, remotePort));
				delete response;
				response = NULL;
				continue;
			}

			m_pendingRequests[newId]->m_response = response;
			m_pendingRequests[newId] = NULL;
			response = NULL;

			if (newId == id) {
				m_isReading = false;

				if (m_nestedCount)
					for (PINDEX i = 0, j = m_oldestId; i < 256; i++, j = (j + 1) & 0xff)
						if (m_readSyncPointIndices[j] != P_MAX_INDEX
							&& m_readSyncPoints[m_readSyncPointIndices[j] & 0xff] != NULL)
						{
							m_readSyncPoints[m_readSyncPointIndices[j] & 0xff]->Signal();
							break;
						}

				delete requestInfo;
				requestInfo = NULL;
				return true;
			} else if(m_readSyncPointIndices[newId] != P_MAX_INDEX
				&& m_readSyncPoints[m_readSyncPointIndices[newId]] != NULL) {
				m_readSyncPoints[m_readSyncPointIndices[newId]]->Signal();
				continue;
			}
		} else {
			result = (syncPoint != NULL && syncPoint->Wait(timeout));
			if (!result)
				break;
				
			result = FALSE;
				
			PWaitAndSignal lock(m_readMutex);

			if (m_pendingRequests[id] == NULL) {
				FreeReadSyncPoint(m_readSyncPointIndices[id]);
				m_readSyncPointIndices[id] = P_MAX_INDEX;
				if (m_nestedCount)
					m_nestedCount--;
				delete requestInfo;
				requestInfo = NULL;
				return true;
			}

			if (!m_isReading) {
				m_isReading = shouldRead = true;
					
				FreeReadSyncPoint(m_readSyncPointIndices[id]);
				m_readSyncPointIndices[id] = P_MAX_INDEX;
				syncPoint = NULL;
				if (m_nestedCount)
					m_nestedCount--;
				continue;
			}
				
			continue;
		}

		if (!result)
			break;

	} while (PTime() < (startTime + timeout));

	{
		PWaitAndSignal lock(m_readMutex);

		m_pendingRequests[id] = NULL;
		
		if (m_readSyncPointIndices[id] != P_MAX_INDEX) {
			FreeReadSyncPoint(m_readSyncPointIndices[id]);
			m_readSyncPointIndices[id] = P_MAX_INDEX;
			if (m_nestedCount)
				m_nestedCount--;
		}

		if (m_isReading && shouldRead) {
			m_isReading = false;

			if (m_nestedCount)
				for (PINDEX i = m_oldestId, j = 0; j < 256; j++, i = (i + 1) & 0xff)
					if (m_readSyncPointIndices[i] != P_MAX_INDEX
						&& m_readSyncPoints[m_readSyncPointIndices[i] & 0xff] != NULL)
					{
						m_readSyncPoints[m_readSyncPointIndices[i] & 0xff]->Signal();
						break;
					}
		}
	}

	delete requestInfo;
	requestInfo = NULL;
	return result ? true : false;
}

bool RadiusSocket::SendRequest( 
	const RadiusPDU* request, 
	const Address& serverAddress, 
	WORD serverPort
	)
{
	if (!IsOpen() || request == NULL || !request->IsValid())
		return false;

	PWaitAndSignal lock(m_writeMutex);
	if (WriteTo(request, request->GetLength(), serverAddress, serverPort))
		return true;

	PTRACE(5, "RADIUS\tError sending UDP packet ("
		<< GetErrorCode(LastWriteError) << '/'
		<< GetErrorNumber(LastWriteError) << ": "
		<< GetErrorText(LastWriteError) << " (id:" 
		<< (PINDEX)request->GetId() << ')'
		);
	return false;
}

void RadiusSocket::RefreshIdCache(const time_t now)
{
	const PINDEX lastId = ((m_nextId >= m_oldestId) 
		? m_nextId : ((PINDEX)m_nextId + 256));
	const long timeout = m_idCacheTimeout.GetSeconds();
	PINDEX i = m_oldestId;
	
	while (i++ < lastId && (m_idTimestamps[m_oldestId] + timeout) < now)
		++m_oldestId;
}

PINDEX RadiusSocket::GenerateNewId()
{
	const PTime now;
	const time_t nowInSeconds = now.GetTimeInSeconds();
	
	RefreshIdCache(nowInSeconds);
	
	if (((m_nextId + 1) & 0xff) == m_oldestId)
		return P_MAX_INDEX;
	else {
		m_recentRequestTime = now;
		m_idTimestamps[m_nextId] = nowInSeconds;
		return m_nextId++;
	}
}

RadiusClient::RadiusClient( 
	/// primary RADIUS server
	const PString& servers, 
	/// local address for RADIUS client
	const PString& address,
	/// default secret shared between the client and the server
	const PString& sharedSecret
	) : m_sharedSecret((const char*)sharedSecret), 
	m_authPort(RadiusClient::GetDefaultAuthPort()),
	m_acctPort(RadiusClient::GetDefaultAcctPort()),
	m_portBase(1024), m_portMax(65535),
	m_requestTimeout(DefaultRequestTimeout), 
	m_idCacheTimeout(DefaultIdCacheTimeout),
	m_socketDeleteTimeout(DefaultSocketDeleteTimeout),
	m_numRetries(DefaultRetries), m_roundRobinServers(false),
	m_localAddress(GNUGK_INADDR_ANY)
{
	GetServersFromString(servers);
	
	if (!address) {
		if (!PIPSocket::IsLocalHost(address)) {
			PTRACE(1, "RADIUS\tSpecified local client address " << address
				<< " is not bound to any local interface");
		} else {
			PIPSocket::GetHostAddress(address, m_localAddress);
		}
	}

	if (PTrace::CanTrace(4)) {
		ostream& s = PTrace::Begin(4, __FILE__, __LINE__);
		const std::streamsize indent = s.precision() + 2;
		s << "RADIUS\tCreated instance of RADIUS client (local if: "
			<< m_localAddress << ", default ports: " << m_authPort << ',' 
			<< m_acctPort << ") for RADIUS servers group:";
		for (unsigned i = 0; i < m_radiusServers.size(); i++)
			s << '\n' << setw(indent + m_radiusServers[i]->m_serverAddress.GetLength()) 
				<< m_radiusServers[i]->m_serverAddress << " (auth port: "
				<< (m_radiusServers[i]->m_authPort == 0 ? m_authPort : m_radiusServers[i]->m_authPort)
				<< ", acct port: " << (m_radiusServers[i]->m_acctPort == 0 ? m_acctPort : m_radiusServers[i]->m_acctPort)
				<< ')';
		PTrace::End(s);
	}
}

RadiusClient::RadiusClient( 
	PConfig & config, /// config that contains RADIUS settings
	const PString& sectionName /// config section with the settings
	)
	: m_sharedSecret(Toolkit::Instance()->ReadPassword(sectionName, "SharedSecret")),
	m_authPort((WORD)config.GetInteger(sectionName, "DefaultAuthPort", 
		RadiusClient::GetDefaultAuthPort())),
	m_acctPort((WORD)config.GetInteger(sectionName, "DefaultAcctPort", 
		RadiusClient::GetDefaultAcctPort())),
	m_portBase(1024), m_portMax(65535),
	m_requestTimeout(config.GetInteger(sectionName, "RequestTimeout",
		DefaultRequestTimeout)),
	m_idCacheTimeout(config.GetInteger(sectionName, "IdCacheTimeout",
		DefaultIdCacheTimeout)),
	m_socketDeleteTimeout(config.GetInteger(sectionName, "SocketDeleteTimeout",
		DefaultSocketDeleteTimeout)),
	m_numRetries(config.GetInteger(sectionName, "RequestRetransmissions",
		DefaultRetries)),
	m_roundRobinServers(config.GetBoolean(
		sectionName, "RoundRobinServers", TRUE)),
	m_localAddress(GNUGK_INADDR_ANY)
{
	GetServersFromString(config.GetString(sectionName, "Servers", ""));
		
	const PString addr = config.GetString(sectionName, "LocalInterface", "");
	
	if (!addr) {
		if (!PIPSocket::IsLocalHost(addr)) {
			PTRACE(2, "RADIUS\tSpecified local client address '" << addr 
				<< "' is not bound to any local interface");
		} else {
			PIPSocket::GetHostAddress(addr, m_localAddress);
		}
	}

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
			m_portBase = (WORD)p1;
			m_portMax = (WORD)p2;
		}
	}

	if (PTrace::CanTrace(4)) {
		ostream& os = PTrace::Begin(4, __FILE__, __LINE__);
		const std::streamsize indent = os.precision() + 2;
		os << "RADIUS\tCreated instance of RADIUS client (local if: "
			<< m_localAddress << ", default ports: " << m_authPort << ',' 
			<< m_acctPort << ") for RADIUS servers group:";
		for (unsigned i = 0; i < m_radiusServers.size(); i++)
			os << '\n' << setw(indent + m_radiusServers[i]->m_serverAddress.GetLength()) 
				<< m_radiusServers[i]->m_serverAddress << " (auth port: "
				<< (m_radiusServers[i]->m_authPort == 0 ? m_authPort : m_radiusServers[i]->m_authPort)
				<< ", acct port: " << (m_radiusServers[i]->m_acctPort == 0 ? m_acctPort : m_radiusServers[i]->m_acctPort)
				<< ')';
		PTrace::End(os);
	}
}

RadiusClient::~RadiusClient()
{
	socket_iterator iter = m_activeSockets.begin();
	while (iter != m_activeSockets.end()) {
		RadiusSocket *s = *iter;
		iter = m_activeSockets.erase(iter);
		delete s;
	}
		
	for (unsigned i = 0; i < m_radiusServers.size(); i++)
		delete m_radiusServers[i];
	m_radiusServers.clear();
}

void RadiusClient::GetServersFromString(const PString & servers)
{
	const PStringArray tokens = servers.Tokenise(" ;,", FALSE);
	for (PINDEX i = 0; i < tokens.GetSize(); i++) {
		PStringArray serverTokens;
		if (tokens[i].Left(1) == "[") {
			// IPv6 address
			PINDEX ip_end = tokens[i].Find(']');
			serverTokens.SetSize(1);
			serverTokens[0] = tokens[i].Mid(1, ip_end-1);
			const PStringArray detailsTokens = tokens[i].Mid(ip_end+1).Tokenise(":", FALSE);
			for (PINDEX j=0; j < detailsTokens.GetSize(); ++j) {
				serverTokens.SetSize(serverTokens.GetSize()+1);
				serverTokens[j+1] = detailsTokens[j];
			}
		} else {
			// IPv4 or DNS names
			serverTokens = tokens[i].Tokenise(":", FALSE);
		}
		if (serverTokens.GetSize() > 0) {
			const PString serverAddress = serverTokens[0].Trim();
			if (!serverAddress) {
				RadiusServer* const server = new RadiusServer();
				server->m_serverAddress = serverAddress;
				server->m_authPort = 0;
				server->m_acctPort = 0;
				if (serverTokens.GetSize() >= 2)
					server->m_authPort = (WORD)(serverTokens[1].AsInteger());
				if (serverTokens.GetSize() >= 3)
					server->m_acctPort = (WORD)(serverTokens[2].AsInteger());
				if (serverTokens.GetSize() >= 4)
					server->m_sharedSecret = serverTokens[3].Trim();
				m_radiusServers.push_back(server);
			}
		}
	}
}

bool RadiusClient::SetIdCacheTimeout( 
	const PTimeInterval & timeout /// new time interval
	)
{
	PWaitAndSignal lock(m_socketMutex);
	
	if (timeout < PTimeInterval(1000))
		return false;
		
	m_idCacheTimeout = timeout;
	socket_const_iterator i = m_activeSockets.begin();
	while (i != m_activeSockets.end()) {
		(*i)->SetIdCacheTimeout(timeout);
		++i;
	}
			
	return true;
}

bool RadiusClient::MakeRequest( 
	const RadiusPDU & requestPDU, /// PDU with request packet
	RadiusPDU * & responsePDU /// filled with PDU received from RADIUS server
	)
{
	if (!requestPDU.IsValid())
		return false;

	bool retransmission = false;
	RadiusSocket* socket = NULL;
	unsigned char id;
	const unsigned numServers = m_radiusServers.size();
	const PString * secret = NULL;
	
	for (unsigned i = 0; i < (m_roundRobinServers ? m_numRetries * numServers : numServers); i++)
	{
		const unsigned serverIndex = i % numServers;
		const PTime now;

		const RadiusServer* const server = m_radiusServers[serverIndex];
		const WORD authPort = server->m_authPort == 0 ? m_authPort : server->m_authPort;
		const WORD acctPort = server->m_acctPort == 0 ? m_acctPort : server->m_acctPort;
		const WORD serverPort = IsAcctPDU(requestPDU) ? acctPort : authPort;
		const PString* const oldSecret = secret;

		secret = server->m_sharedSecret.IsEmpty() ? &m_sharedSecret : &server->m_sharedSecret;

		bool secretChanged = secret != oldSecret && oldSecret != NULL 
			&& secret->Compare(*oldSecret) != PString::EqualTo;

		PIPSocket::Address serverAddress;
		if (!PIPSocket::GetHostAddress(server->m_serverAddress, serverAddress)
			|| !serverAddress.IsValid()) {
			PTRACE(3, "RADIUS\tCould not get IP address for RADIUS server "
				"host: " << server->m_serverAddress
				);
			continue;
		}

		for (unsigned j = 0; j < (m_roundRobinServers ? 1 : m_numRetries); j++) {
 			RadiusPDU* const clonedRequestPDU = new RadiusPDU(requestPDU);

			bool requireNewId = false;

			if (secretChanged || requireNewId || !retransmission)
				if (!GetSocket(socket, id)) {
					PTRACE(3, "RADIUS\tSocket allocation failed");
					delete clonedRequestPDU;
					return false;
				}
			
			secretChanged = false;
			
			clonedRequestPDU->SetId(id);

			PMessageDigest5 md5;
			clonedRequestPDU->SetAuthenticator(*secret, md5);
			if (!clonedRequestPDU->EncryptPasswords(*secret, md5)) {
				PTRACE(3, "RADIUS\tCould not encrypt passwords "
					"(id:" << (PINDEX)(clonedRequestPDU->GetId()) << ')'
					);
				delete clonedRequestPDU;
				return false;
			}
	
			if( PTrace::CanTrace(3) ) {
				ostream& strm = PTrace::Begin(3, __FILE__, __LINE__);
				strm << "RADIUS\tSending PDU to RADIUS server "
					<< server->m_serverAddress << " (" << AsString(serverAddress, serverPort)
					<< ')' << " from " << (*socket) << ", PDU: ";
				if( PTrace::CanTrace(5) )
					strm << *clonedRequestPDU;
				else
					strm << PMAP_CODE_TO_NAME(clonedRequestPDU->GetCode())
						<< ", id " << (PINDEX)(clonedRequestPDU->GetId());
				PTrace::End(strm);
			}
			RadiusPDU* response = NULL;
			
			retransmission = true;
			
			if (!socket->MakeRequest(clonedRequestPDU, serverAddress, 
					serverPort, response)) {
				PTRACE(3, "RADIUS\tReceive response from RADIUS server failed "
					"(id:" << (PINDEX)(clonedRequestPDU->GetId()) << ')'
					);
				delete clonedRequestPDU;
				continue;
			}

			if (!VerifyResponseAuthenticator(
					clonedRequestPDU, response, *secret)) {
				PTRACE(5, "RADIUS\tReceived PDU (id: " 
					<< (PINDEX)clonedRequestPDU->GetId()
					<< ") has an invalid response authenticator"
					);
				delete clonedRequestPDU;
				continue;
			}

			delete clonedRequestPDU;

			if (PTrace::CanTrace(3)) {
				ostream& strm = PTrace::Begin(3, __FILE__, __LINE__);
				strm << "RADIUS\tReceived PDU from RADIUS server "
					<< server->m_serverAddress << " (" << AsString(serverAddress, serverPort)
					<< ')' << " by socket " << (*socket) << ", PDU: ";
				if (PTrace::CanTrace(5))
					strm << (*response);
				else
					strm << PMAP_CODE_TO_NAME(response->GetCode()) << ", id "
						<< (PINDEX)(response->GetId());
				PTrace::End(strm);
			}

			responsePDU = response;
			return true;
		}
	}

	return false;
}

bool RadiusClient::SendRequest( 
	const RadiusPDU & requestPDU /// PDU with request packet
	)
{
	if (!requestPDU.IsValid())
		return false;

	RadiusSocket* socket = NULL;
	unsigned char id;
	RadiusPDU* clonedRequestPDU = NULL;

	if (m_radiusServers.empty()) {
		PTRACE(1, "RADIUS\tNo RADIUS servers configured");
		return false;
	}

	const RadiusServer*	const server = m_radiusServers.front();
	const WORD authPort = server->m_authPort == 0 ? m_authPort : server->m_authPort;
	const WORD acctPort = server->m_acctPort == 0 ? m_acctPort : server->m_acctPort;
	const WORD serverPort = IsAcctPDU(requestPDU) ? acctPort : authPort;
	const PString& secret = server->m_sharedSecret.IsEmpty()
		? m_sharedSecret : server->m_sharedSecret;

	PIPSocket::Address serverAddress;
	if (!PIPSocket::GetHostAddress(server->m_serverAddress, serverAddress)
			|| !serverAddress.IsValid()) {
		PTRACE(3, "RADIUS\tCould not get IP address for RADIUS server host: "
			<< server->m_serverAddress
			);
		return false;
	}

	clonedRequestPDU = new RadiusPDU(requestPDU);

	if (!GetSocket(socket, id)) {
		PTRACE(3, "RADIUS\tSocket allocation failed");
		delete clonedRequestPDU;
		return false;
	}

	clonedRequestPDU->SetId(id);

	PMessageDigest5 md5;
	clonedRequestPDU->SetAuthenticator(secret, md5);
	if (!clonedRequestPDU->EncryptPasswords(secret, md5)) {
		PTRACE(3, "RADIUS\tCould not encrypt passwords "
			"(id:" << (PINDEX)(clonedRequestPDU->GetId()) << ')'
			);
		delete clonedRequestPDU;
		return false;
	}

	if (PTrace::CanTrace(3)) {
		ostream& strm = PTrace::Begin(3, __FILE__, __LINE__);
		strm << "RADIUS\tSending PDU to RADIUS server "
			<< server->m_serverAddress << " (" << AsString(serverAddress, serverPort)
			<< ')' << " from " << (*socket) << ", PDU: ";
		if (PTrace::CanTrace(5))
			strm << *clonedRequestPDU;
		else
			strm << PMAP_CODE_TO_NAME(clonedRequestPDU->GetCode()) << ", id "
				<< (PINDEX)(clonedRequestPDU->GetId());
		PTrace::End(strm);
	}

	if (!socket->SendRequest(clonedRequestPDU, serverAddress, serverPort)) {
		PTRACE(3, "RADIUS\tError sending RADIUS request (id:" << (PINDEX)id << ')');
		delete clonedRequestPDU;
		return false;
	}

	delete clonedRequestPDU;
	return true;
}

bool RadiusClient::VerifyResponseAuthenticator(
	const RadiusPDU* request,
	const RadiusPDU* response,
	const PString& secret
	)
{
	PMessageDigest5 md5;
	PMessageDigest::Result digest;
	const PINDEX len = response->GetLength();
	
	md5.Process(response, RadiusPDU::AuthenticatorOffset);
	md5.Process(request->GetAuthenticator(), RadiusPDU::AuthenticatorLength);
	if (len > RadiusPDU::FixedHeaderLength)
		md5.Process(
			reinterpret_cast<const char*>(response) + RadiusPDU::FixedHeaderLength,
			len - RadiusPDU::FixedHeaderLength
			);
	
	const PINDEX secretLength = secret.GetLength();
	if (secretLength > 0)
		md5.Process((const char*)secret, secretLength);

	md5.CompleteDigest(digest);

	return digest.GetSize() == RadiusPDU::AuthenticatorLength
		&& memcmp(digest.GetPointer(), response->GetAuthenticator(),
			RadiusPDU::AuthenticatorLength) == 0;
}

bool RadiusClient::IsAcctPDU(const RadiusPDU & pdu) const
{
	const unsigned char c = pdu.GetCode();
	return (c == RadiusPDU::AccountingRequest) 
		|| (c == RadiusPDU::AccountingResponse)
		|| (c == RadiusPDU::AccountingStatus)
		|| (c == RadiusPDU::AccountingMessage);
}

bool RadiusClient::GetSocket(RadiusSocket*& socket, unsigned char& id)
{
	PWaitAndSignal lock(m_socketMutex);
	
	const socket_iterator endIter = m_activeSockets.end();
	socket_iterator si = m_activeSockets.begin();
	
	// find a first socket that is not busy (has at least one ID that can
	// be used for a request)
	while (si != endIter) {
		const PINDEX newId = (*si)->GenerateNewId();
		if (newId != P_MAX_INDEX) {
			id = (unsigned char)newId;
			break;
		} else
			++si;
	}

	// refresh state of remaining sockets (reclaim unused request IDs)
	// and delete sockets that have not been used for a long time
	const PTime now;
	socket_iterator i = m_activeSockets.begin();
	
	while (i != endIter) {
		if (i == si) {
			++i;
			continue;
		}
		
		(*i)->RefreshIdCache(now.GetTimeInSeconds());
		
		if ((*i)->CanDestroy() 
			&& ((*i)->GetRecentRequestTime() + m_socketDeleteTimeout) < now) {
			RadiusSocket *s = *i;
			i = m_activeSockets.erase(i);
			delete s;
		} else
			++i;
	}

	if (si != endIter) {
		socket = *si;
		return true;	
	}

	// all sockets are busy, create a new one
	PRandom random;
	PINDEX randCount = (unsigned)(m_portMax-m_portBase+1) / 3;
	RadiusSocket* newSocket = NULL;
		
	if (randCount > 0)
		do {
			PINDEX portIndex = random % (unsigned)(m_portMax-m_portBase+1);

			delete newSocket;
			newSocket = NULL;

			if (m_localAddress == GNUGK_INADDR_ANY)
				newSocket = CreateSocket((WORD)(m_portBase + portIndex));
			else
				newSocket = CreateSocket(m_localAddress, (WORD)(m_portBase + portIndex));
		} while ((newSocket == NULL || !newSocket->IsOpen()) && --randCount);

	if (newSocket == NULL || !newSocket->IsOpen())
		for (WORD p = m_portBase; p < m_portMax; p++) {
			delete newSocket;
			newSocket = NULL;

			if (m_localAddress == GNUGK_INADDR_ANY)
				newSocket = CreateSocket(p);
			else
				newSocket = CreateSocket(m_localAddress, p);
				
			if (newSocket->IsOpen())
				break;
		}
			
	if (newSocket == NULL || !newSocket->IsOpen()) {
		delete newSocket;
		return false;
	}
		
	newSocket->SetReadTimeout(m_requestTimeout);
	newSocket->SetWriteTimeout(m_requestTimeout);
	newSocket->SetIdCacheTimeout(m_idCacheTimeout);
	
	
	const PINDEX newId = newSocket->GenerateNewId();
	if (newId == P_MAX_INDEX) {
		delete newSocket;
		return false;
	}
	
	m_activeSockets.push_back(newSocket);
	PTRACE(5, "RADIUS\tCreated new RADIUS client socket: " << (*newSocket));
		
	socket = newSocket;
	id = (unsigned char)newId;
	return true;
}

RadiusSocket* RadiusClient::CreateSocket(const PIPSocket::Address & addr, WORD port)
{
	return new RadiusSocket(addr, port);
}
	
RadiusSocket* RadiusClient::CreateSocket(WORD port)
{
	return new RadiusSocket(port);
}

#endif /* HAS_RADIUS */
