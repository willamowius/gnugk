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

#ifndef GKPROFILE_H
#define GKPROFILE_H "@(#) $Id$"

#ifdef P_SOLARIS
#define map stl_map
#endif


#include <map>
#include <q931.h>
#include "Toolkit.h"

// Classes to store information read form e.g. LDAP
// necessary for e.g. routing decisions
using std::map;
typedef std::map<PString, PString> SpecialDialClass;
typedef SpecialDialClass::value_type SpecialDialValuePair;

class CallProfile {
public:
	CallProfile();
	virtual ~CallProfile();


	enum Conversions {
		TreatAsInternational = Q931::InternationalType,
		TreatAsNational      = Q931::NationalType,
		TreatAsLocal         = Q931::SubscriberType,
		LeaveUntouched
	} ;

        const PString & GetH323ID() const ;
        const BOOL IsCPE() const ;
        const BOOL IsGK() const ;
	const BOOL IsTrunkGW() const ;
        const BOOL HonorsARJincompleteAddress() const ;
	const BOOL WhiteListBeforeBlackList() const ;
	const BOOL ConvertToLocal() const ;
	const BOOL GetPrependCallbackAC() const ;
	const BOOL SendReleaseCompleteOnDRQ() const {return FALSE ;} // Stub-funtion
        const PStringList & GetTelephoneNumbers() const ;
        const PStringToString & GetSpecialDials() const ;
        const PString & GetMainTelephoneNumber() const ;
	const PString & GetSubscriberNumber() const ;
        const PString & GetClir() const ;
        const PString & GetLac() const ;
        const PString & GetNac() const ;
        const PString & GetInac() const ;
        const PString & GetCC() const ;
	const PString & GetNDC_IC() const ;
        const PString & GetCgPN() ;

	const PStringList & GetBlackList() const ;
	const PStringList & GetWhiteList() const ;

	const long int GetCallTimeout();
	const PTimeInterval GetStatusEnquiryInterval();

	// These two will change the numbering conversion functions to treat the
	// number as International (TreatAsInternational), National (TreatAsNational)
	// Local (TreatAsLocal) or relay on the TON (LeaveUntouched).
	const enum CallProfile::Conversions TreatCallingPartyNumberAs() const ;
	const enum CallProfile::Conversions TreatCalledPartyNumberAs() const ;


	void debugPrint(void) const;

        // Set accessor methods
        void SetH323ID(PString &h323id) ;
        void SetIsCPE(BOOL isCPE) ;
	void SetIsGK(BOOL isGK) ;
        void SetTelephoneNumbers(PStringList &telNums) ;
        void SetSpecialDials(PStringToString & spcDials) ;
        void SetMainTelephoneNumber(PString &mainTelNum);
	void SetSubscriberNumber (PString &SN) ;
        void SetClir(PString &clir) ;
        void SetLac(PString &lac) ;
        void SetNac(PString &nac) ;
        void SetInac(PString &inac) ;
        void SetHonorsARJincompleteAddress(BOOL honor) ;
	void SetWhiteListBeforeBlackList(BOOL wbb) ;
	void SetPrependCallbackAC(BOOL pcac);
	void SetConvertToLocal(BOOL cl);
	void SetTreatCallingPartyNumberAs(enum CallProfile::Conversions tcpna);
	void SetTreatCalledPartyNumberAs(enum CallProfile::Conversions tcpna);

	void SetCC(const PString &cc) ;
	void SetNDC_IC(const PString &ndc);
        void SetCgPN(PString &cgPN) ;

	void SetStatusEnquiryInterval(int timeout); // Timeout in seconds
	void SetCallTimeout(long int timeout); // Timeout in seconds

	void SetBlackList(PStringList &bl) ;
	void SetWhiteList(PStringList &wl) ;

protected:
        PString         m_h323id;                     // H323ID
	BOOL            m_honorsARJincompleteAddress; // honorsARJincompleteAddress
        PStringList     m_telephoneNumbers;           // telephone numbers
        PStringToString m_specialDials;               // emergency call numbers
        PString         m_mainTelephoneNumber;        // main telephone number
	PString         m_subscriberNumber;           // Subscriber Number (i.e. the "80" in 49 5246 80-1234)
        PString         m_clir;                       // CLIR
        PString         m_lac;                        // local access code
        PString         m_nac;                        // national access code
        PString         m_inac;                       // international access code
        PString         m_cc;                         // country code
	PString         m_ndc_ic;                     // national destination code
        PString         m_cgPN;                       // calling party number for CDR generation
        BOOL            m_isCPE;                      // CPE flag
	BOOL            m_isGK;                       // Gatekeeper client Flag
	BOOL            m_WhiteListBeforeBlackList;   // if true do WhitelistBlacklist else BlacklistWhitelistAnalysis
	BOOL            m_PrependCallbackAC;          // Prepend Callback AccessCode to the number.
	BOOL            m_ConvertToLocal;             // Convert Numbers to most local numbers.
	E164_AnalysedNumber m_e164number;             // The maintelephonenumber as E164Number
	PTimeInterval   m_StatusEnquiryInterval;      // Timeinterval between 2 StatusEnquiry pings.

	enum Conversions m_TreatCallingPartyNumberAs; // Treat Calling Party Number as international, national, local or use the TON-field
	enum Conversions m_TreatCalledPartyNumberAs;  // See above but Called Party Number
	PStringList     m_BlackList;                  // Blacklist of "bad" prefices
	PStringList     m_WhiteList;                  // Whitelist of "good" prefices
protected:
	PMutex          m_lock;
};

class CallingProfile : public CallProfile {
public:
        CallingProfile() {};
	~CallingProfile() {}; // Do nothing.
}; // CallingProfile

class CalledProfile : public CallProfile {
public:
        CalledProfile() : m_releasecause(Q931::NormalCallClearing) {};
        CalledProfile(PString &dialedPN, PString &calledPN);
	~CalledProfile();

        // Get accessor methods
        const PString & GetDialedPN() const ;
        const PString & GetCalledPN() const ;
	const PString & GetCallingPN() const ;
        const enum Q931::TypeOfNumberCodes  GetDialedPN_TON() const ;
	const enum Q931::TypeOfNumberCodes  GetAssumedDialedPN_TON() const ;
	const PString & GetAssumedDialedPN() const ;
	BOOL ReleaseCauseIsSet() const;
	const enum Q931::CauseValues GetReleaseCause() const ;
	const H225_DisengageReason GetDisengageReason() const ;

        void SetDialedPN(PString &dialedPN,
			 const enum Q931::TypeOfNumberCodes dialedPN_TON = Q931::UnknownType);
	void SetDialedPN(PString &dialedPN, const enum Q931::NumberingPlanCodes dialedPN_PLAN,
			 const enum Q931::TypeOfNumberCodes dialedPN_TON,
			 const enum H225_ScreeningIndicator::Enumerations dialedPN_SI = H225_ScreeningIndicator::e_userProvidedNotScreened);
	void SetAssumedDialedPN(PString &dialedPN, const enum Q931::NumberingPlanCodes dialedPN_PLAN,
				const enum Q931::TypeOfNumberCodes dialedPN_TON);
	void SetDialedPN_TON(const enum Q931::TypeOfNumberCodes dialedPN_TON);
        void SetCalledPN(PString &calledPN);
	void SetCallingPN(PString &callingPN, const enum Q931::NumberingPlanCodes callingPN_PLAN = Q931::UnknownPlan,
			  const enum Q931::TypeOfNumberCodes callingPN_TON = Q931::UnknownType,
			  const enum H225_ScreeningIndicator::Enumerations callingPN_SI = H225_ScreeningIndicator::e_userProvidedNotScreened,
			  const enum H225_PresentationIndicator::Choices callingPN_PI = H225_PresentationIndicator::e_presentationAllowed);
	void SetReleaseCause(const enum Q931::CauseValues cause);
	void SetReleaseCause(const H225_DisengageReason cause);

private:
	// the dialed.*-information is the "raw" data collected from H225Ras or Q.931. The "assumed"
	// data is the collected "raw" information with addition of a possible TON from a prefix analysis
	// or a E164 number analysis. The party number will *not* be rewritten in any way other than
	// striping the prefix (inac/nac/lac).


	// The ScreeningIndicator member is (at the moment) not used, but provided for later use (in CDR
	// generation for instance)
	enum Q931::TypeOfNumberCodes m_dialedPN_TON; // type of number for dialed PN
	enum Q931::NumberingPlanCodes m_dialedPN_PLAN;
	H225_ScreeningIndicator m_dialedPN_SI;
        PString m_dialedPN; // dialed party number

	BOOL m_release_is_set;

	enum Q931::TypeOfNumberCodes m_assumeddialedPN_TON; // type of number for dialed PN
	enum Q931::NumberingPlanCodes m_assumeddialedPN_PLAN;
	enum Q931::CauseValues m_releasecause;
        PString m_assumeddialedPN; // dialed party number

        PString m_calledPN; // called party number
	PString m_callingPN; // calling party number as in Q.931-Setup after converting to international
	mutable PMutex m_lock;
}; // CalledProfile

// End of: Classes to store information read from e.g. LDAP



#endif // GKPROFILE_H
