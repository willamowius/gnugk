// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Nils Bokermann <Nils.Bokermann@mediaWays.net>
//
// PURPOSE OF THIS FILE:  Objects to keep Data collected from/of Endpoints (Profiles)
//
// - Automatic Version Information via RCS:
//   $Id$
//   $Source$
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//

#include <ptlib.h>
#include <ptlib/sockets.h>
#include "GkProfile.h"
#include "Toolkit.h"
#include "ANSI.h"

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

const int
CallProfile::GetMinPrefixLen() const
{
	PWaitAndSignal lock(m_lock);
	return m_minprefixlength;
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

const long int
CallProfile::GetCallTimeout()
{ // Not yet...
	return -1 ;
}
const PTimeInterval
CallProfile::GetStatusEnquiryInterval()
{
	PWaitAndSignal lock(m_lock);
	return m_StatusEnquiryInterval;
}

// Set accessor methods
void
CallProfile::SetH323ID(const PString &h323id)
{
	PWaitAndSignal lock(m_lock);
	m_h323id = *(dynamic_cast<PString *> (h323id.Clone()));;
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
	m_subscriberNumber = *(dynamic_cast<PString *> (SN.Clone()));
}

void
CallProfile::SetClir(PString &clir)
{
	PWaitAndSignal lock(m_lock);
	m_clir = *(dynamic_cast<PString *> (clir.Clone()));;
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
CallProfile::SetMinPrefixLen(int len)
{
	PWaitAndSignal lock(m_lock);
	m_minprefixlength = len;
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
CallProfile::SetStatusEnquiryInterval(int timeout)
{ // Timeout in seconds
	PWaitAndSignal lock(m_lock);
	m_StatusEnquiryInterval = PTimeInterval(0,timeout);
	if(timeout<4)
		m_StatusEnquiryInterval = PTimeInterval(0);
}
void
CallProfile::SetCallTimeout(long int timeout)
{ // Timeout in seconds
// do nothing
}

void
CallProfile::debugPrint(void)  const
{
	PWaitAndSignal lock(m_lock);
	PTRACE(5, ANSI::GRE << "Call Profile:" << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  H323ID=" << GetH323ID() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  CPE=" << IsCPE() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  Telno=" << GetTelephoneNumbers() << ANSI::OFF);
	const PStringToString &spMap = GetSpecialDials();
	PTRACE(5, spMap.GetSize() << " SpecialDials:");
	for (PINDEX i=0; i < spMap.GetSize(); i++) {
		PTRACE(5, "\t" << spMap.GetKeyAt(i) << "--->" << spMap.GetDataAt(i));
	}
	PTRACE(5, ANSI::GRE << "  MainNo=" << GetMainTelephoneNumber() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  SubsNo=" << GetSubscriberNumber() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  CLIR=" << GetClir() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  Lac=" << GetLac() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  Nac=" << GetNac() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  Inac=" << GetInac() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  HonorsARJIncompleteAddr=" << HonorsARJincompleteAddress() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  CC=" << GetCC() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  PrependCallbackAC=" << GetPrependCallbackAC() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  ConvertNumberToLocal= " << ConvertToLocal() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  TreatCallingPartyNumberAs=" << TreatCallingPartyNumberAs() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  TreatCalledPartyNumberAs=" << TreatCalledPartyNumberAs() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  BlackList=" << GetBlackList() << ANSI::OFF);
	PTRACE(5, ANSI::GRE << "  WhiteList=" << GetWhiteList() << ANSI::OFF);
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
	m_releasecause = Q931::UnknownCauseIE;
	m_release_is_set = FALSE;
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

BOOL CalledProfile::ReleaseCauseIsSet() const
{
	return m_release_is_set;
}

const H225_DisengageReason
CalledProfile::GetDisengageReason() const
{
	H225_DisengageReason rsn;
	if(Q931::UserBusy == m_releasecause ||
	   Q931::NormalCallClearing == m_releasecause ||
	   Q931::NormalUnspecified == m_releasecause) {
		rsn.SetTag(H225_DisengageReason::e_normalDrop);
	} else {
		rsn.SetTag(H225_DisengageReason::e_forcedDrop);
	}
	return rsn;
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

	if(!m_release_is_set){
		m_release_is_set = TRUE;
		m_releasecause = cause;
	}
}

void
CalledProfile::SetReleaseCause(const H225_DisengageReason cause)
{
	PWaitAndSignal lock(m_lock);
	if(!m_release_is_set) {
		m_release_is_set = TRUE;
		switch(cause.GetTag()) {
		case H225_DisengageReason::e_forcedDrop:
			m_releasecause = Q931::CallRejected;
			break;
		case H225_DisengageReason::e_normalDrop:
			m_releasecause = Q931::NormalCallClearing;
			break;
		case H225_DisengageReason::e_undefinedReason:
			m_releasecause=Q931::UnknownCauseIE;
			break;
		default:
			m_releasecause=Q931::UnknownCauseIE;
		}
	}
}
// End of: Classes to store information read from e.g. LDAP
