//////////////////////////////////////////////////////////////////
//
// H.323 utility functions that should migrate into the OpenH323 library
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	991129	initial version (Henrik Joerring)
//
//////////////////////////////////////////////////////////////////


#include "h323util.h"
#include "h323pdu.h"
//#include "q931.h"


/*
H225_CallIdentifier *GetCallIdentifier(const Q931 & m_q931)
{
	if (m_q931.HasIE(Q931::UserUserIE)) {
		H225_H323_UserInformation signal;

		PPER_Stream q(m_q931.GetIE(Q931::UserUserIE));
		if (signal.Decode(q)) {
			H225_H323_UU_PDU & pdu = signal.m_h323_uu_pdu;
			H225_H323_UU_PDU_h323_message_body & body = pdu.m_h323_message_body;
			H225_Setup_UUIE & setup = body;

			if (setup.HasOptionalField(H225_Setup_UUIE::e_callIdentifier))
				return &setup.m_callIdentifier;
		} else {
			PTRACE(5, "GK\tERROR DECODING Q931.UserInformation!");
		}
	} else {
		PTRACE(3, "GK\tERROR Q931 has no UUIE!!\n");
	}
	return 0; // no CallId
}

bool SendRasPDU(H225_RasMessage &ras_msg, const H225_TransportAddress & dest)
{
	if (dest.GetTag() != H225_TransportAddress::e_ipAddress) {
		PTRACE(3, "No IP address to send!" );
		return false;
	}

	PBYTEArray wtbuf(4096);
	PPER_Stream wtstrm(wtbuf);
	ras_msg.Encode(wtstrm);
	wtstrm.CompleteEncoding();

	const H225_TransportAddress_ipAddress & ip = dest;
	PIPSocket::Address ipaddress(ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3]);

	PTRACE(2, "GK\tSend to " << ipaddress << " [" << ip.m_port << "] : " << ras_msg.GetTagName());
	PTRACE(3, "GK\t" << endl << setprecision(2) << ras_msg);

	PUDPSocket Sock;
	return Sock.WriteTo(wtstrm.GetPointer(), wtstrm.GetSize(), ipaddress, ip.m_port) != 0;
}
*/

PString AsString(const H225_TransportAddress & ta)
{
	PStringStream stream;
	stream << ta;
	return stream;
}

PString AsDotString(const H225_TransportAddress & ip)
{
	return (ip.GetTag() == H225_TransportAddress::e_ipAddress) ?
		AsString((const H225_TransportAddress_ipAddress &)ip) : PString();
}

PString AsString(const H225_TransportAddress_ipAddress & ip)
{
	return PString(PString::Printf, "%d.%d.%d.%d:%u",
		ip.m_ip[0], ip.m_ip[1], ip.m_ip[2], ip.m_ip[3],
		ip.m_port.GetValue());
}

PString AsString(const H225_EndpointType & terminalType)
{
	PString terminalTypeString;
			
	if (terminalType.HasOptionalField(H225_EndpointType::e_terminal))
		terminalTypeString = ",terminal";

	if (terminalType.HasOptionalField(H225_EndpointType::e_gateway))
		terminalTypeString += ",gateway";
	
	if (terminalType.HasOptionalField(H225_EndpointType::e_mcu))
		terminalTypeString += ",mcu";

	if (terminalType.HasOptionalField(H225_EndpointType::e_gatekeeper))
		terminalTypeString += ",gatekeeper";

/* vendor seems always to be set - this clutters up the display
	if (terminalType.HasOptionalField(H225_EndpointType::e_vendor))
		terminalTypeString += ",vendor";
*/

	if (terminalTypeString.IsEmpty())
		terminalTypeString = ",unknown";
	
	return terminalTypeString.Mid(1);
}

PString AsString(const H225_AliasAddress & terminalAlias, BOOL includeAliasName)
{
	PString aliasString;

	if(!terminalAlias.IsValid())
		return includeAliasName ? "invalid:UnknownType" : "invalid";

	switch (terminalAlias.GetTag()) {
		case H225_AliasAddress::e_dialedDigits:
		case H225_AliasAddress::e_url_ID:
		case H225_AliasAddress::e_email_ID:
		case H225_AliasAddress::e_h323_ID:
		case H225_AliasAddress::e_transportID:
		case H225_AliasAddress::e_partyNumber:
			aliasString = H323GetAliasAddressString(terminalAlias);
			if (includeAliasName) {
				aliasString += ":" + terminalAlias.GetTagName();
			}
			return aliasString;
			break;
	}

	return includeAliasName ? "none:UnknownType" : "none";
}


PString AsString(const H225_ArrayOf_AliasAddress & terminalAlias, BOOL includeAliasName)
{
	PString aliasListString = "";

	for(PINDEX cnt = 0; cnt < terminalAlias.GetSize(); cnt ++ )
	{

		aliasListString += AsString(terminalAlias[cnt], includeAliasName);

		if (cnt < (terminalAlias.GetSize() - 1)) {
			aliasListString += "=";
		}
	}
	return (aliasListString);
}


PString AsString(const PASN_OctetString & Octets)
{
	PString result;
	if (Octets.GetDataLength() > 0) {
		result = PString(PString::Printf, "%02x", Octets[0]);
		for (PINDEX i = 1; i < Octets.GetDataLength(); ++i)
			result += PString(PString::Printf, " %02x", Octets[i]);
	}
	return result;
}


bool AliasEqualN(H225_AliasAddress AliasA, H225_AliasAddress AliasB, int n)
{
	if (AliasA.GetTag() != AliasB.GetTag())
		return FALSE;	// not of same type
	else
	{
		PString AliasStrA = H323GetAliasAddressString(AliasA);
		PString AliasStrB = H323GetAliasAddressString(AliasB);
		return (strncmp(AliasStrA, AliasStrB, n) == 0);
	}
};


// convert a socket IP address into an H225 transport address
H225_TransportAddress SocketToH225TransportAddr(const PIPSocket::Address & Addr, WORD Port)
{
    H225_TransportAddress Result;

    Result.SetTag( H225_TransportAddress::e_ipAddress );
    H225_TransportAddress_ipAddress & ResultIP = Result;

    ResultIP.m_ip[0] = Addr.Byte1();
    ResultIP.m_ip[1] = Addr.Byte2();
    ResultIP.m_ip[2] = Addr.Byte3();
    ResultIP.m_ip[3] = Addr.Byte4();
    ResultIP.m_port  = Port;

    return Result;
}

