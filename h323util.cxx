//////////////////////////////////////////////////////////////////
//
// H.323 utility functions that should migrate into the OpenH323 library
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	991129	initial version (Henrik Joerring)
//  000106  towi: changed all PTRACE info from level 4 to level 5
//
//////////////////////////////////////////////////////////////////


#include "h323util.h"
#include "ANSI.h"


PString AsString(const H225_TransportAddress & ta) 
{
	PStringStream schtream;

	schtream << ta;
	PString schtring = (PString) schtream;
	cerr << ANSI::CYA << schtring << ANSI::OFF << endl;
	return schtring;
}


PString AsString(const H225_EndpointType & terminalType)
{
	PString terminalTypeString;
			
	if (terminalType.HasOptionalField(H225_EndpointType::e_terminal))
		terminalTypeString = "terminal";

	if (terminalType.HasOptionalField(H225_EndpointType::e_gateway)) {
		if (terminalTypeString == "")
			terminalTypeString = "gateway";
		else
			terminalTypeString += ",gateway";
	}
	
	if (terminalType.HasOptionalField(H225_EndpointType::e_mcu)) {
		if (terminalTypeString == "")
			terminalTypeString = "mcu";
		else
			terminalTypeString += ",mcu";
	}
	  /*
	if (terminalType.HasOptionalField(H225_EndpointType::e_vendor)) {
		if (firstElement) {
			firstElement = false;
			terminalTypeString = "vendor";
		}
		else {
			terminalTypeString += ",vendor";
		}
	}
	  */
	if (terminalTypeString == "")
		terminalTypeString = "unknown";
	
	return(terminalTypeString);
}


PString AsString(const H225_AliasAddress & terminalAlias, BOOL includeAliasName)
{
	PString aliasString = "";
	BOOL foundAlias = FALSE;

	if(!terminalAlias.IsValid())
		return includeAliasName ? "invalid:UnknownType" : "invalid";

	switch (terminalAlias.GetTag()) {
		case H225_AliasAddress::e_e164:
		case H225_AliasAddress::e_url_ID: //fall through for common treatment of IA5String type aliases
		case H225_AliasAddress::e_email_ID: //fall through for common treatment of IA5Strings type aliases
			aliasString += ((PASN_IA5String&)(terminalAlias).GetObject()).GetValue();
			foundAlias = TRUE;
			break;
		case H225_AliasAddress::e_h323_ID:
			aliasString += ((PASN_BMPString&)(terminalAlias).GetObject()).GetValue();
			foundAlias = TRUE;
			break;
		case H225_AliasAddress::e_transportID:
			aliasString += "transportID provided - not currently supported";
			  //aliasListString += ((H225_TransportAddress&)(obj_rr.m_terminalAlias[cnt]).GetObject()).GetValue();
			foundAlias = TRUE;
			break;
		case H225_AliasAddress::e_partyNumber:
			aliasString += "partyNumber provided - not currently supported";
			  //aliasListString += ((H225_PartyNumber&)(obj_rr.m_terminalAlias[cnt]).GetObject()).GetValue();
			foundAlias = TRUE;
			break;
	}
	// Add comments on next 2 lines to remove tagname in messages.
	if (foundAlias) {
		if ( includeAliasName) {
			aliasString += ":";
			aliasString += terminalAlias.GetTagName();
		}
		
	}
	else {
		if (includeAliasName) {
			aliasString = "none:UnknownType";
		}
		else {
			aliasString = "none";
		}
	}
		
	return (aliasString);
}


PString AsString(const H225_ArrayOf_AliasAddress & terminalAlias, BOOL includeAliasName)
{
	PString aliasListString = "";
	PINDEX cnt;

	for( cnt = 0; cnt < terminalAlias.GetSize(); cnt ++ )
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
		PString AliasStrA = ((PASN_BMPString&)AliasA.GetObject()).GetValue();
		PString AliasStrB = ((PASN_BMPString&)AliasB.GetObject()).GetValue();
		return (strncmp(AliasStrA, AliasStrB, n) == 0);
	}
};
