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

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id";
static const char vcHid[] = GKPROFILE_H;
#endif /* lint */


// Classes to store information read form e.g. LDAP
// necessary for e.g. routing decisions

CallProfile::~CallProfile()
{
	m_lock.Wait();
}

const PString &
CallProfile::GetH323ID() const
{
	PWaitAndSignal lock(m_lock);
	return m_h323id;
}

const BOOL
CallProfile::IsCPE() const
{
	PWaitAndSignal lock(m_lock);
	return m_isCPE;
} // Customer Promise Equipment

const BOOL
CallProfile::IsGK() const
{
	PWaitAndSignal lock(m_lock);
	return m_isGK;
} // Gatekeeper client

const BOOL
CallProfile::IsTrunkGW() const
{
	PWaitAndSignal lock(m_lock);
	return !(m_isCPE || m_isGK) ;
}

const BOOL
CallProfile::HonorsARJincompleteAddress() const
{
	PWaitAndSignal lock(m_lock);
	return m_honorsARJincompleteAddress;
}

const BOOL
CallProfile::WhiteListBeforeBlackList() const
{
	PWaitAndSignal lock(m_lock);
	return m_WhiteListBeforeBlackList;
}

const BOOL
CallProfile::ConvertToLocal() const
{
	PWaitAndSignal lock(m_lock);
	return m_ConvertToLocal;
} // Not yet implemented

const BOOL
CallProfile::GetPrependCallbackAC() const
{
	PWaitAndSignal lock(m_lock);
	return m_PrependCallbackAC;
}

const enum
CallProfile::Conversions CallProfile::TreatCallingPartyNumberAs() const
{
	PWaitAndSignal lock(m_lock);
	return m_TreatCallingPartyNumberAs; };
const enum CallProfile::Conversions CallProfile::TreatCalledPartyNumberAs() const {return m_TreatCalledPartyNumberAs;
};

const PStringList &
CallProfile::GetTelephoneNumbers() const
{
	PWaitAndSignal lock(m_lock);
	return m_telephoneNumbers;
}

const PStringToString &
CallProfile::GetSpecialDials() const
{
	PWaitAndSignal lock(m_lock);
	return m_specialDials;
}

const PString &
CallProfile::GetMainTelephoneNumber() const
{
	PWaitAndSignal lock(m_lock);
	return m_mainTelephoneNumber;
}

const PString &
CallProfile::GetSubscriberNumber() const
{
	PWaitAndSignal lock(m_lock);
	return m_subscriberNumber;
}

const PString &
CallProfile::GetClir() const
{
	PWaitAndSignal lock(m_lock);
	return m_clir;
}

const PString &
CallProfile::GetLac() const
{
	PWaitAndSignal lock(m_lock);
	return m_lac;
}

const PString &
CallProfile::GetNac() const
{
	PWaitAndSignal lock(m_lock);
	return m_nac;
}

const PString &
CallProfile::GetInac() const
{
	PWaitAndSignal lock(m_lock);
	return m_inac;
}

const PString &
CallProfile::GetCC() const
{
	PWaitAndSignal lock(m_lock);
	return m_cc;
}

const PString &
CallProfile::GetNDC_IC() const
{
	PWaitAndSignal lock(m_lock);
	return m_ndc_ic;
}

const PString &
CallProfile::GetCgPN()
{
	PWaitAndSignal lock(m_lock);
	return m_cgPN;
}


const PStringList &
CallProfile::GetBlackList() const
{
	PWaitAndSignal lock(m_lock);
	return m_BlackList;
}

const PStringList &
CallProfile::GetWhiteList() const
{
	PWaitAndSignal lock(m_lock);
	return m_WhiteList;
}


// Set accessor methods
void
CallProfile::SetH323ID(PString &h323id)
{
	PWaitAndSignal lock(m_lock);
	m_h323id = h323id;
}

void
CallProfile::SetIsCPE(BOOL isCPE)
{
	PWaitAndSignal lock(m_lock);
	m_isCPE = isCPE;
}

void
CallProfile::SetIsGK(BOOL isGK)
{
	PWaitAndSignal lock(m_lock);
	m_isGK = isGK;
}

void
CallProfile::SetTelephoneNumbers(PStringList &telNums)
{
	PWaitAndSignal lock(m_lock);
	m_telephoneNumbers = telNums;
}

void
CallProfile::SetSpecialDials(PStringToString & spcDials)
{
	PWaitAndSignal lock(m_lock);
	m_specialDials = spcDials;
}

void
CallProfile::SetSubscriberNumber(PString &SN)
{
	PWaitAndSignal lock(m_lock);
	m_subscriberNumber = SN;
}

void
CallProfile::SetClir(PString &clir)
{
	PWaitAndSignal lock(m_lock);
	m_clir = clir;
}

void
CallProfile::SetLac(PString &lac)
{
	PWaitAndSignal lock(m_lock);
	m_lac = lac;
}

void
CallProfile::SetNac(PString &nac)
{
	PWaitAndSignal lock(m_lock);
	m_nac = nac;
}

void
CallProfile::SetInac(PString &inac)
{
	PWaitAndSignal lock(m_lock);
	m_inac = inac;
}

void
CallProfile::SetHonorsARJincompleteAddress(BOOL honor)
{
	PWaitAndSignal lock(m_lock);
	m_honorsARJincompleteAddress = honor;
}

void
CallProfile::SetWhiteListBeforeBlackList(BOOL wbb)
{
	PWaitAndSignal lock(m_lock);
	m_WhiteListBeforeBlackList = wbb;
}

void
CallProfile::SetPrependCallbackAC(BOOL pcac)
{
	PWaitAndSignal lock(m_lock);
	m_PrependCallbackAC = pcac;
}

void
CallProfile::SetConvertToLocal(BOOL cl)
{
	PWaitAndSignal lock(m_lock);
	m_ConvertToLocal = cl ;
}

void
CallProfile::SetCC(const PString &cc)
{
	PWaitAndSignal lock(m_lock);
	m_cc = cc;
}

void
CallProfile::SetNDC_IC(const PString &ndc)
{
	PWaitAndSignal lock(m_lock);
	m_ndc_ic = ndc;
}

void
CallProfile::SetCgPN(PString &cgPN)
{
	PWaitAndSignal lock(m_lock);
	m_cgPN = cgPN;
}

void
CallProfile::SetTreatCallingPartyNumberAs(enum CallProfile::Conversions tcpna)
{
	PWaitAndSignal lock(m_lock);
	m_TreatCallingPartyNumberAs = tcpna;
}

void
CallProfile::SetTreatCalledPartyNumberAs(enum CallProfile::Conversions tcpna)
{
	PWaitAndSignal lock(m_lock);
	m_TreatCalledPartyNumberAs = tcpna;
}

void
CallProfile::SetBlackList(PStringList &bl)
{
	PWaitAndSignal lock(m_lock);
	m_BlackList = bl;
}

void
CallProfile::SetWhiteList(PStringList &wl)
{
	PWaitAndSignal lock(m_lock);
	m_WhiteList = wl;
}

void
CallProfile::debugPrint(void)  const
{
	PWaitAndSignal lock(m_lock);
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
	PTRACE(5, "ConvertNumberToLocal= " << ConvertToLocal());
	PTRACE(5, "TreatCallingPartyNumberAs=" << TreatCallingPartyNumberAs());
	PTRACE(5, "TreatCalledPartyNumberAs=" << TreatCalledPartyNumberAs());
	PTRACE(5, "BlackList=" << GetBlackList());
	PTRACE(5, "WhiteList=" << GetWhiteList());
}

CallProfile::CallProfile() : m_PrependCallbackAC(FALSE),
			     m_ConvertToLocal(FALSE),
			     m_TreatCallingPartyNumberAs(LeaveUntouched),
			     m_TreatCalledPartyNumberAs(LeaveUntouched)
{
	m_honorsARJincompleteAddress = TRUE;
	m_isCPE = FALSE;
	m_WhiteListBeforeBlackList = FALSE; // BlacklistBeforeWhiteList, default nonblocking
};

void
CallProfile::SetMainTelephoneNumber(PString &mainTelNum)
{
	PWaitAndSignal lock(m_lock);
	m_mainTelephoneNumber = mainTelNum;
	m_e164number = mainTelNum;
}
//   callED Profile

CalledProfile::CalledProfile(PString &dialedPN, PString &calledPN)
{
	PWaitAndSignal lock(m_lock);
        SetDialedPN(dialedPN);
        SetCalledPN(calledPN);
	m_dialedPN_TON=Q931::UnknownType;
	m_dialedPN_PLAN=Q931::UnknownPlan;
}

CalledProfile::~CalledProfile()
{
	m_lock.Wait();
}

const PString &
CalledProfile::GetDialedPN() const
{
	PWaitAndSignal lock(m_lock);
	return m_dialedPN;
}

const PString &
CalledProfile::GetCalledPN() const
{
	PWaitAndSignal lock(m_lock);
	return m_calledPN;
}

const PString &
CalledProfile::GetCallingPN() const
{
	PWaitAndSignal lock(m_lock);
	return m_callingPN;
}

const enum Q931::TypeOfNumberCodes
CalledProfile::GetDialedPN_TON() const
{
	PWaitAndSignal lock(m_lock);
	return m_dialedPN_TON;
}

const enum Q931::TypeOfNumberCodes
CalledProfile::GetAssumedDialedPN_TON() const
{
	PWaitAndSignal lock(m_lock);
	return m_assumeddialedPN_TON;
}

const PString &
CalledProfile::GetAssumedDialedPN() const
{
	PWaitAndSignal lock(m_lock);
	return m_assumeddialedPN;
}

const enum Q931::CauseValues
CalledProfile::GetReleaseCause() const
{
	PWaitAndSignal lock(m_lock);
	return m_releasecause;

}
void
CalledProfile::SetDialedPN(PString &dialedPN,
			   const enum Q931::TypeOfNumberCodes dialedPN_TON)
{
	PTRACE(5, "Setting DialedPN to " << dialedPN);
	PWaitAndSignal lock(m_lock);
	m_dialedPN = dialedPN;
	m_dialedPN_TON = dialedPN_TON;
}

void
CalledProfile::SetDialedPN(PString &dialedPN,
			   const enum Q931::NumberingPlanCodes dialedPN_PLAN,
			   const enum Q931::TypeOfNumberCodes dialedPN_TON,
			   const enum H225_ScreeningIndicator::Enumerations dialedPN_SI)
// The dialed PN as provided in Q.931 or H225Ras
{
	PTRACE(5, "Setting DialedPN to " << dialedPN);
	PWaitAndSignal lock(m_lock);
	m_dialedPN = dialedPN;
	m_dialedPN_TON = dialedPN_TON;
	m_dialedPN_PLAN = dialedPN_PLAN;
	m_dialedPN_SI.SetTag(dialedPN_SI);

}

void
CalledProfile::SetAssumedDialedPN(PString &dialedPN,
				  const enum Q931::NumberingPlanCodes dialedPN_PLAN,
				  const enum Q931::TypeOfNumberCodes dialedPN_TON)
// The "dialedPN" as assumed in Numbering Conversions (not necessary international Type)
{
	PTRACE(5, "Setting DialedPN to " << dialedPN);
	PWaitAndSignal lock(m_lock);
	m_assumeddialedPN = dialedPN;
	m_assumeddialedPN_TON = dialedPN_TON;
	m_assumeddialedPN_PLAN = dialedPN_PLAN;
}

void
CalledProfile::SetDialedPN_TON(const enum Q931::TypeOfNumberCodes dialedPN_TON)
{
	PWaitAndSignal lock(m_lock);
	m_dialedPN_TON = dialedPN_TON;
}

void
CalledProfile::SetCalledPN(PString &calledPN)
{
	PTRACE(5, "Setting CalledPN to " << calledPN);
	PWaitAndSignal lock(m_lock);
	m_calledPN = calledPN;
}

void
CalledProfile::SetCallingPN(PString &callingPN, const enum Q931::NumberingPlanCodes callingPN_PLAN,
			    const enum Q931::TypeOfNumberCodes callingPN_TON,
	     const enum H225_ScreeningIndicator::Enumerations callingPN_SI,
	     const enum H225_PresentationIndicator::Choices callingPN_PI)
{
	// PLAN, TON, ScreeningIndicator, PresentationIndicator are not yet used, but reserved
	// for future use. Please do not change.
	PWaitAndSignal lock(m_lock);
	m_callingPN = callingPN;
}

void
CalledProfile::SetReleaseCause(const enum Q931::CauseValues cause)
{
	PWaitAndSignal lock(m_lock);
	m_releasecause = cause;
}
// End of: Classes to store information read from e.g. LDAP
