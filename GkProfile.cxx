// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// Objects to keep Data collected from/of Endpoints (Profiles)
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <ptlib/sockets.h>
#include "GkProfile.h"
#include "Toolkit.h"

// Classes to store information read form e.g. LDAP
// necessary for e.g. routing decisions

CallProfile::~CallProfile() {}

const PString & CallProfile::GetH323ID() const { return m_h323id;}
const BOOL CallProfile::IsCPE() const { return m_isCPE; } // Customer Promise Equipment
const BOOL CallProfile::IsGK() const { return m_isGK; } // Gatekeeper client
const BOOL CallProfile::IsTrunkGW() const { return !(m_isCPE || m_isGK) ; }
const BOOL CallProfile::HonorsARJincompleteAddress() const { return m_honorsARJincompleteAddress; }
const BOOL CallProfile::WhiteListBeforeBlackList() const { return m_WhiteListBeforeBlackList; }
const BOOL CallProfile::ConvertToLocal() const { return FALSE ; } // Not yet implemented
const BOOL CallProfile::GetPrependCallbackAC() const { return m_PrependCallbackAC; }
const enum CallProfile::Conversions CallProfile::TreatCallingPartyNumberAs() const {return m_TreatCallingPartyNumberAs; };
const enum CallProfile::Conversions CallProfile::TreatCalledPartyNumberAs() const {return m_TreatCalledPartyNumberAs; };
const PStringList & CallProfile::GetTelephoneNumbers() const { return m_telephoneNumbers; }
const PStringToString & CallProfile::GetSpecialDials() const { return m_specialDials; }
const PString & CallProfile::GetMainTelephoneNumber() const { return m_mainTelephoneNumber; }
const PString & CallProfile::GetSubscriberNumber() const { return m_subscriberNumber; }
const PString & CallProfile::GetClir() const { return m_clir; }
const PString & CallProfile::GetLac() const { return m_lac; }
const PString & CallProfile::GetNac() const { return m_nac; }
const PString & CallProfile::GetInac() const { return m_inac; }
const PString & CallProfile::GetCC() const { return m_cc; }
const PString & CallProfile::GetNDC_IC() const { return m_e164number.GetNDC_IC().GetValue(); } // inconsistency with GetCC()
const PString & CallProfile::GetCgPN() { return m_cgPN; }

const PStringList & CallProfile::GetBlackList() const { return m_BlackList; }
const PStringList & CallProfile::GetWhiteList() const { return m_WhiteList; }

// Set accessor methods
void CallProfile::SetH323ID(PString &h323id) { m_h323id = h323id; }
void CallProfile::SetIsCPE(BOOL isCPE) { m_isCPE = isCPE; }
void CallProfile::SetIsGK(BOOL isGK) {m_isGK = isGK;}
void CallProfile::SetTelephoneNumbers(PStringList &telNums) { m_telephoneNumbers = telNums; }
void CallProfile::SetSpecialDials(PStringToString & spcDials) { m_specialDials = spcDials; }
void CallProfile::SetSubscriberNumber(PString &SN) { m_subscriberNumber = SN; }
void CallProfile::SetClir(PString &clir) { m_clir = clir; }
void CallProfile::SetLac(PString &lac) { m_lac = lac; }
void CallProfile::SetNac(PString &nac) { m_nac = nac; }
void CallProfile::SetInac(PString &inac) { m_inac = inac; }
void CallProfile::SetHonorsARJincompleteAddress(BOOL honor) { m_honorsARJincompleteAddress = honor; }
void CallProfile::SetWhiteListBeforeBlackList(BOOL wbb) {m_WhiteListBeforeBlackList = wbb; }
void CallProfile::SetPrependCallbackAC(BOOL pcac) {m_PrependCallbackAC = pcac;}
void CallProfile::SetConvertToLocal(BOOL cl) { m_ConvertToLocal = cl ;}
void CallProfile::SetCC(PString &cc) { m_cc = cc; }
void CallProfile::SetCgPN(PString &cgPN) { m_cgPN = cgPN; }
void CallProfile::SetTreatCallingPartyNumberAs(enum CallProfile::Conversions tcpna) { m_TreatCallingPartyNumberAs = tcpna; }
void CallProfile::SetTreatCalledPartyNumberAs(enum CallProfile::Conversions tcpna)  { m_TreatCalledPartyNumberAs = tcpna; }
void CallProfile::SetBlackList(PStringList &bl) { m_BlackList = bl; }
void CallProfile::SetWhiteList(PStringList &wl) { m_WhiteList = wl; }


void
CallProfile::debugPrint(void)  const
{
		PTRACE(5, "Calling profile:");
		PTRACE(5, "H323ID=" << GetH323ID());
		PTRACE(5, "CPE=" << IsCPE());
		PTRACE(5, "Telno=" << GetTelephoneNumbers());
		const PStringToString &spMap = GetSpecialDials();
		PTRACE(5, spMap.GetSize() << " SpecialDials:");
		for (PINDEX i=0; i < spMap.GetSize(); i++) {
			PTRACE(5, "\t" << spMap.GetKeyAt(i) << "--->" << spMap.GetDataAt(i));
		}
		PTRACE(5, "MainNo=" << GetMainTelephoneNumber());
		PTRACE(5, "SubsNo=" << GetSubscriberNumber());
		PTRACE(5, "CLIR=" << GetClir());
		PTRACE(5, "Lac=" << GetLac());
		PTRACE(5, "Nac=" << GetNac());
		PTRACE(5, "Inac=" << GetInac());
		PTRACE(5, "HonorsARJIncompleteAddr=" << HonorsARJincompleteAddress());
		PTRACE(5, "CC=" << GetCC());
		PTRACE(5, "PrependCallbackAC=" << GetPrependCallbackAC());
		PTRACE(5, "BlackList=" << GetBlackList());
		PTRACE(5, "WhiteList=" << GetWhiteList());
}

CallProfile::CallProfile() : m_TreatCallingPartyNumberAs(LeaveUntouched),
			     m_TreatCalledPartyNumberAs(LeaveUntouched)
{
	m_honorsARJincompleteAddress = TRUE;
	m_isCPE = FALSE;
	m_WhiteListBeforeBlackList = FALSE; // BlacklistBeforeWhiteList, default nonblocking
};

void
CallProfile::SetMainTelephoneNumber(PString &mainTelNum)
{
	m_mainTelephoneNumber = mainTelNum;
	m_e164number = mainTelNum;
}
//   callED Profile

CalledProfile::CalledProfile(PString &dialedPN, PString &calledPN)
{
        SetDialedPN(dialedPN);
        SetCalledPN(calledPN);
	m_dialedPN_TON=Q931::UnknownType;
	m_dialedPN_PLAN=Q931::UnknownPlan;
}

void
CalledProfile::SetDialedPN(PString &dialedPN,
			   const enum Q931::TypeOfNumberCodes dialedPN_TON)
{
	m_dialedPN = dialedPN;
	m_dialedPN_TON = dialedPN_TON;
}

void
CalledProfile::SetDialedPN(PString &dialedPN,
			   const enum Q931::NumberingPlanCodes dialedPN_PLAN,
			   const enum Q931::TypeOfNumberCodes dialedPN_TON,
			   const enum H225_ScreeningIndicator::Enumerations dialedPN_SI)
{
	m_dialedPN = dialedPN;
	m_dialedPN_TON = dialedPN_TON;
	m_dialedPN_PLAN = dialedPN_PLAN;
	m_dialedPN_SI.SetTag(dialedPN_SI);

}

void
CalledProfile::SetDialedPN_TON(const enum Q931::TypeOfNumberCodes dialedPN_TON)
{
	m_dialedPN_TON = dialedPN_TON;
}

void
CalledProfile::SetCalledPN(PString &calledPN)
{
	PTRACE(5, "Setting CalledPN to" << calledPN);
	m_calledPN = calledPN;
}

void
CalledProfile::SetCallingPN(PString &callingPN, const enum Q931::NumberingPlanCodes callingPN_PLAN,
			    const enum Q931::TypeOfNumberCodes callingPN_TON,
	     const enum H225_ScreeningIndicator::Enumerations callingPN_SI,
	     const enum H225_PresentationIndicator::Choices callingPN_PI)
{
	m_callingPN = callingPN;
}

// End of: Classes to store information read from e.g. LDAP
