//////////////////////////////////////////////////////////////////
//
// H.323 utility functions that should migrate into the OpenH323 library
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	991129	initial version (Henrik Joerring)
//
//////////////////////////////////////////////////////////////////


#include "h323util.h"
#include "h323pdu.h"


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


PString AsString(const H225_TransportAddress & ta)
{
	PStringStream stream;
	stream << ta;
	return stream;
}

PString AsDotString(const H225_TransportAddress & ip)
{
	return (ip.GetTag() == H225_TransportAddress::e_ipAddress) ?
		AsString((const H225_TransportAddress_ipAddress &)ip) : "";
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
		terminalTypeString = "terminal";

	if (terminalType.HasOptionalField(H225_EndpointType::e_gateway)) {
		if (terminalTypeString != "")
			terminalTypeString += ",";
		terminalTypeString += "gateway";
	}
	
	if (terminalType.HasOptionalField(H225_EndpointType::e_mcu)) {
		if (terminalTypeString != "")
			terminalTypeString += ",";
		terminalTypeString += "mcu";
	}

/* vendor seems always to be set - this clutters up the display
	if (terminalType.HasOptionalField(H225_EndpointType::e_vendor)) {
		if (terminalTypeString != "")
			terminalTypeString += ",";
		terminalTypeString += "vendor";
	}
*/

	if (terminalTypeString == "")
		terminalTypeString = "unknown";
	
	return(terminalTypeString);
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
	char MsgBuffer[1024];
	char HexVal[10];

	for (PINDEX i = 0; i < Octets.GetDataLength(); i++)
	{
		sprintf(HexVal, " %02x", Octets[i]);
		strcat(MsgBuffer, HexVal);
	};

	return PString(MsgBuffer);
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

