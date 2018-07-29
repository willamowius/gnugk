//////////////////////////////////////////////////////////////////
//
// gkauth.cxx
//
// Copyright (c) 2001-2018, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"
#include <ptlib.h>
#include <h235.h>
#include <h323pdu.h>
#include <h235auth.h>

#include "gk_const.h"
#include "h323util.h"
#include "stl_supp.h"
#include "Toolkit.h"
#include "RasTbl.h"
#include "RasPDU.h"
#include "sigmsg.h"
#include "Routing.h"
#include "gkauth.h"

#if H323_H350
extern const char *H350Section;
#include <ptclib/pldap.h>
#include "h350/h350.h"
#endif // H323_H350

#ifdef HAS_H46018
#include <h460/h4601.h>
#endif

#ifdef P_SSL
#include <openssl/rand.h>
#endif // P_SSL

#include <ptclib/http.h>

#ifdef HAS_LIBCURL
#include <curl/curl.h>
#endif // HAS_LIBCURL


namespace {
const char* const GkAuthSectionName = "Gatekeeper::Auth";
}

using std::stable_sort;
using std::for_each;
using std::find_if;
using std::greater;


ARQAuthData::ARQAuthData(
	/// an endpoint requesting admission
	const endptr & ep,
	/// call record matching this ARQ (if any)
	const callptr & call
	) : m_rejectReason(-1), m_callDurationLimit(-1),
	m_requestingEP(ep),	m_call(call), m_billingMode(-1),
	m_proxyMode(CallRec::ProxyDetect),
	m_clientAuthId(0)
{
}

ARQAuthData::ARQAuthData(const ARQAuthData & obj)
	: m_rejectReason(obj.m_rejectReason),
	m_callDurationLimit(obj.m_callDurationLimit),
	m_requestingEP(obj.m_requestingEP), m_call(obj.m_call),
	m_billingMode(obj.m_billingMode), m_routeToAlias(obj.m_routeToAlias),
	m_destinationRoutes(obj.m_destinationRoutes), m_proxyMode(obj.m_proxyMode),
	m_clientAuthId(0)
{
}

ARQAuthData & ARQAuthData::operator=(const ARQAuthData & obj)
{
	if (this != &obj) {
		m_rejectReason = obj.m_rejectReason;
		m_callDurationLimit = obj.m_callDurationLimit;
		m_requestingEP = obj.m_requestingEP;
		m_call = obj.m_call;
		m_billingMode = obj.m_billingMode;
		m_proxyMode = obj.m_proxyMode;
		m_clientAuthId = obj.m_clientAuthId;
		m_routeToAlias = obj.m_routeToAlias;
		m_destinationRoutes = obj.m_destinationRoutes;
	}
	return *this;
}

void ARQAuthData::SetRouteToAlias(const H225_ArrayOf_AliasAddress & alias)
{
	m_routeToAlias = alias;
}

void ARQAuthData::SetRouteToAlias(const PString & alias, int tag)
{
	m_routeToAlias.SetSize(1);
	H323SetAliasAddress(alias, m_routeToAlias[0], tag);
}

SetupAuthData::SetupAuthData(
	/// call associated with the message (if any)
	const callptr & call,
	/// is the Setup message from a registered endpoint
	bool fromRegistered,
	/// did the Setup come in over TLS
	bool overTLS,
    /// did the Setup come from a neighbor gatekeeper
	bool fromNeighbor
	) : m_rejectReason(-1), m_rejectCause(-1), m_callDurationLimit(-1),
	m_call(call), m_fromRegistered(fromRegistered),
	m_proxyMode(CallRec::ProxyDetect),
	m_clientAuthId(0), m_overTLS(overTLS), m_fromNeighbor(fromNeighbor)
{
}

SetupAuthData::SetupAuthData(const SetupAuthData & obj)
	: m_rejectReason(obj.m_rejectReason), m_rejectCause(obj.m_rejectCause),
	m_callDurationLimit(obj.m_callDurationLimit), m_call(obj.m_call),
	m_fromRegistered(obj.m_fromRegistered),
	m_routeToAlias(obj.m_routeToAlias), m_destinationRoutes(obj.m_destinationRoutes),
	m_proxyMode(obj.m_proxyMode), m_clientAuthId(0), m_overTLS(false)
{
}

SetupAuthData & SetupAuthData::operator=(const SetupAuthData & obj)
{
	if (this != &obj) {
		m_rejectReason = obj.m_rejectReason;
		m_rejectCause = obj.m_rejectCause;
		m_callDurationLimit = obj.m_callDurationLimit;
		m_call = obj.m_call;
		m_fromRegistered = obj.m_fromRegistered;
		m_proxyMode = obj.m_proxyMode;
		m_clientAuthId = obj.m_clientAuthId;
		m_routeToAlias = obj.m_routeToAlias;
		m_destinationRoutes = obj.m_destinationRoutes;
		m_overTLS = obj.m_overTLS;
	}

	return *this;
}

SetupAuthData::~SetupAuthData()
{
}

void SetupAuthData::SetRouteToAlias(const H225_ArrayOf_AliasAddress & alias)
{
	m_routeToAlias = alias;
}

void SetupAuthData::SetRouteToAlias(const PString & alias, int tag)
{
	m_routeToAlias.SetSize(1);
	H323SetAliasAddress(alias, m_routeToAlias[0], tag);
}


// class GkAuthenticator
GkAuthenticator::GkAuthenticator(
	const char* name, /// a name for the module (to be used in the config file)
	unsigned supportedRasChecks, /// RAS checks supported by this module
	unsigned supportedMiscChecks /// non-RAS checks supported by this module
	)
	: NamedObject(name), m_defaultStatus(e_fail), m_controlFlag(e_Required),
	m_enabledRasChecks(~0U), m_supportedRasChecks(supportedRasChecks),
	m_enabledMiscChecks(~0U), m_supportedMiscChecks(supportedMiscChecks),
	m_config(GkConfig())
{
	const PStringArray control(m_config->GetString(GkAuthSectionName, name, "").Tokenise(";,"));
	if (control.GetSize() > 0) {
		const PString controlStr = control[0].Trim();
		if (strcasecmp(name, "default") == 0)
			m_controlFlag = e_Sufficient,
			m_defaultStatus = Toolkit::AsBool(controlStr) ? e_ok : e_fail;
		else if (controlStr *= "optional")
			m_controlFlag = e_Optional, m_defaultStatus = e_next;
		else if (controlStr *= "required")
			m_controlFlag = e_Required, m_defaultStatus = e_fail;
		else if (controlStr *= "sufficient")
			m_controlFlag = e_Sufficient, m_defaultStatus = e_fail;
		else if (controlStr *= "alternative")
			m_controlFlag = e_Alternative, m_defaultStatus = e_next;
		else
			PTRACE(1, "GKAUTH\tInvalid control flag '" << controlStr
				<< "' specified in the config for " << GetName());
	} else
		PTRACE(1, "GKAUTH\tNo control flag specified in the config for module '"
			<< GetName() << '\'');

	std::map<PString, unsigned> rasmap;
	rasmap["GRQ"] = RasInfo<H225_GatekeeperRequest>::flag,
	rasmap["RRQ"] = RasInfo<H225_RegistrationRequest>::flag,
	rasmap["URQ"] = RasInfo<H225_UnregistrationRequest>::flag,
	rasmap["ARQ"] = RasInfo<H225_AdmissionRequest>::flag,
	rasmap["BRQ"] = RasInfo<H225_BandwidthRequest>::flag,
	rasmap["DRQ"] = RasInfo<H225_DisengageRequest>::flag,
	rasmap["LRQ"] = RasInfo<H225_LocationRequest>::flag,
	rasmap["IRQ"] = RasInfo<H225_InfoRequest>::flag;
	rasmap["RAI"] = RasInfo<H225_ResourcesAvailableIndicate>::flag;

	std::map<PString, unsigned> miscmap;
	miscmap["SETUP"] = e_Setup;
	miscmap["SETUPUNREG"] = e_SetupUnreg;
	miscmap["CONNECT"] = e_Connect;
	miscmap["CALLPROCEEDING"] = e_CallProceeding;
	miscmap["ALERTING"] = e_Alerting;
	miscmap["INFORMATION"] = e_Information;
	miscmap["RELEASECOMPLETE"] = e_ReleaseComplete;
	miscmap["FACILITY"] = e_Facility;
	miscmap["PROGRESS"] = e_Progress;
	miscmap["EMPTY"] = e_Empty;
	miscmap["STATUS"] = e_Status;
	miscmap["STATUSINQUIRY"] = e_StatusEnquiry;
	miscmap["SETUPACK"] = e_SetupAck;
	miscmap["NOTIFY"] = e_Notify;

	if (control.GetSize() > 1) {
		m_enabledRasChecks = 0;
		m_enabledMiscChecks = 0;

		for (PINDEX i = 1; i < control.GetSize(); ++i) {
			const PString checkStr = control[i].Trim().ToUpper();
			if (rasmap.find(checkStr) != rasmap.end()) {
				m_enabledRasChecks |= rasmap[checkStr];
				if ((m_supportedRasChecks & rasmap[checkStr]) != rasmap[checkStr]) {
					PTRACE(1, "GKAUTH\t" << GetName() << " does not support '"
						<< control[i] << "' check");
				}
			} else if(miscmap.find(checkStr) != miscmap.end()) {
				m_enabledMiscChecks |= miscmap[checkStr];
				if ((m_supportedMiscChecks & miscmap[checkStr]) != miscmap[checkStr]) {
					PTRACE(1, "GKAUTH\t" << GetName() << " does not support '"
						<< control[i] << "' check");
				}
			} else {
				PTRACE(1, "GKAUTH\tInvalid check flag '" << control[i]
					<< "' specified in the config for " << GetName());
			}
		}
		if ((m_enabledRasChecks & m_supportedRasChecks) == 0
			&& (m_enabledMiscChecks & m_supportedMiscChecks) == 0) {
			PTRACE(1, "GKAUTH\tNo check flags have been specified "
				"in the config for " << GetName() << " - it will be disabled");
		}
	}

	// convert bit flags to human readable names
	PString rasFlagsStr, miscFlagsStr;

	std::map<PString, unsigned>::const_iterator iter = rasmap.begin();
	while (iter != rasmap.end()) {
		if (m_enabledRasChecks & iter->second) {
			if (!rasFlagsStr)
				rasFlagsStr += ' ';
			rasFlagsStr += iter->first;
		}
		++iter;
	}

	iter = miscmap.begin();
	while (iter != miscmap.end()) {
		if (m_enabledMiscChecks & iter->second) {
			if (!miscFlagsStr)
				miscFlagsStr += ' ';
			miscFlagsStr += iter->first;
		}
		++iter;
	}

	if (rasFlagsStr.IsEmpty())
		rasFlagsStr = "NONE";
	if (miscFlagsStr.IsEmpty())
		miscFlagsStr = "NONE";

	PTRACE(1, "GKAUTH\t" << GetName() << " rule added to check RAS: "
		<< rasFlagsStr << ", OTHER: " << miscFlagsStr);

	m_h235Authenticators = NULL;
}

GkAuthenticator::~GkAuthenticator()
{
	delete m_h235Authenticators;
	PTRACE(1, "GKAUTH\t" << GetName() << " rule removed");
}

PString GkAuthenticator::StatusAsString(int status) const
{
	switch(status)
	{
		case e_ok: return "accept";
		case e_fail: return "reject";
		case e_next: return "next";
	}
	return "invalid";
}

int GkAuthenticator::Check(RasPDU<H225_GatekeeperRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_GatekeeperRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(
	/// a request to be authenticated
	RasPDU<H225_RegistrationRequest> & /*request*/,
	/// authorization data (reject reason, ...)
	RRQAuthData & /*authData*/)
{
	return IsRasCheckEnabled(RasInfo<H225_RegistrationRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_UnregistrationRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_UnregistrationRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(
	/// a request to be authenticated
	RasPDU<H225_AdmissionRequest> & /*req*/,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & /*authData*/)
{
	return IsRasCheckEnabled(RasInfo<H225_AdmissionRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_BandwidthRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_BandwidthRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_DisengageRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_DisengageRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_LocationRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_LocationRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_InfoRequest> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_InfoRequest>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(RasPDU<H225_ResourcesAvailableIndicate> &, unsigned &)
{
	return IsRasCheckEnabled(RasInfo<H225_ResourcesAvailableIndicate>::flag)
		? m_defaultStatus : e_next;
}

int GkAuthenticator::Check(
	SetupMsg & /*setup*/,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & /*authData*/)
{
	return (IsMiscCheckEnabled(e_Setup) || IsMiscCheckEnabled(e_SetupUnreg))
		? m_defaultStatus : e_next;
}

int GkAuthenticator::AuthEnum(unsigned msgCode) const
{
    switch (msgCode) {
        case Q931::AlertingMsg:
            return e_Alerting;
        case Q931::CallProceedingMsg:
            return e_CallProceeding;
        case Q931::ConnectMsg:
            return e_Connect;
        case Q931::ProgressMsg:
            return e_Progress;
        case Q931::SetupMsg:
            return e_Setup;
        case Q931::SetupAckMsg:
            return e_SetupAck;
        case Q931::ReleaseCompleteMsg:
            return e_ReleaseComplete;
        case Q931::InformationMsg:
            return e_Information;
        case Q931::NotifyMsg:
            return e_Notify;
        case Q931::StatusMsg:
            return e_Status;
        case Q931::StatusEnquiryMsg:
            return e_StatusEnquiry;
        case Q931::FacilityMsg:
            return e_Facility;
        default:
            return -1;
    }
}

// this method is called for authentication checks not implemented by individual authenticators
int GkAuthenticator::Check(
	Q931 & msg,
	/// authorization data
	Q931AuthData & /*authData*/)
{
    int code = AuthEnum(msg.GetMessageType());
    if (code > 0) {
        return IsMiscCheckEnabled(e_Facility) ? m_defaultStatus : e_next;
    } else {
        return e_next;
    }
}

bool GkAuthenticator::IsH235Capability(
	/// authentication mechanism
	const H235_AuthenticationMechanism & mechanism,
	/// algorithm OID for the given authentication mechanism
	const PASN_ObjectId & algorithmOID
	) const
{
	if (m_h235Authenticators) {
		for (PINDEX i = 0; i < m_h235Authenticators->GetSize(); i++) {
			if ((*m_h235Authenticators)[i].IsCapability(mechanism, algorithmOID)) {
				return true;
			}
		}
	}
	return false;
}

bool GkAuthenticator::IsH235Capable() const
{
	return m_h235Authenticators && m_h235Authenticators->GetSize() > 0;
}

void GkAuthenticator::AppendH235Authenticator(
	H235Authenticator* h235Auth /// H.235 authenticator to append
	)
{
	if (h235Auth) {
		if (m_h235Authenticators == NULL)
			m_h235Authenticators = new H235Authenticators();
		m_h235Authenticators->Append(h235Auth);
	}
}

PString GkAuthenticator::GetUsername(
	/// RRQ message with additional data
	const RasPDU<H225_RegistrationRequest> & request
	) const
{
	const H225_RegistrationRequest& rrq = request;

	PString username;

	if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias))
		username = GetBestAliasAddressString(rrq.m_terminalAlias, false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (username.IsEmpty()) {
		PIPSocket::Address addr;
		if (rrq.m_callSignalAddress.GetSize() > 0
			&& GetIPFromTransportAddr(rrq.m_callSignalAddress[0], addr)
			&& addr.IsValid())
			username = addr.AsString();
		else if (rrq.m_rasAddress.GetSize() > 0
			&& GetIPFromTransportAddr(rrq.m_rasAddress[0], addr)
			&& addr.IsValid())
			username = addr.AsString();
	}

	return username;
}

PString GkAuthenticator::GetUsername(
	/// ARQ message with additional data
	const RasPDU<H225_AdmissionRequest> & request,
	/// additional data
	ARQAuthData & authData
	) const
{
	const H225_AdmissionRequest& arq = request;
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString username;

	/// try to find h323_ID, email_ID or url_ID to use for User-Name
	if (!arq.m_answerCall)
		username = GetBestAliasAddressString(arq.m_srcInfo, true,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID)
			);
	else if (hasCall)
		username = GetBestAliasAddressString(authData.m_call->GetSourceAddress(), true,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (authData.m_requestingEP && (username.IsEmpty()
			|| FindAlias(authData.m_requestingEP->GetAliases(), username) == P_MAX_INDEX))
		username = GetBestAliasAddressString(authData.m_requestingEP->GetAliases(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	/// if no h323_ID, email_ID or url_ID has been found, try to find any alias
	if (username.IsEmpty()) {
		if (!arq.m_answerCall) {
			username = GetBestAliasAddressString(arq.m_srcInfo, false,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
				AliasAddressTagMask(H225_AliasAddress::e_email_ID)
					| AliasAddressTagMask(H225_AliasAddress::e_url_ID));
		} else if (hasCall) {
			username = GetBestAliasAddressString(
				authData.m_call->GetSourceAddress(), true,
				AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
				AliasAddressTagMask(H225_AliasAddress::e_email_ID)
					| AliasAddressTagMask(H225_AliasAddress::e_url_ID));
		}
	}


	if (username.IsEmpty()) {
		PIPSocket::Address addr;
		if (arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)
			&& GetIPFromTransportAddr(arq.m_srcCallSignalAddress, addr)
			&& addr.IsValid())
			username = addr.AsString();
		else if (authData.m_requestingEP
			&& GetIPFromTransportAddr(authData.m_requestingEP->GetCallSignalAddress(), addr)
			&& addr.IsValid())
			username = addr.AsString();
	}

	return username;
}

PString GkAuthenticator::GetUsername(
	const SetupMsg & setup,
	/// additional data
	SetupAuthData & authData
	) const
{
	const bool hasCall = authData.m_call.operator->() != NULL;
	PString username;
	endptr callingEP;
	Q931& q931pdu = setup.GetQ931();
	H225_Setup_UUIE &setupBody = setup.GetUUIEBody();

	if (hasCall)
		callingEP = authData.m_call->GetCallingParty();

	if (setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		username = GetBestAliasAddressString(setupBody.m_sourceAddress, true,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID)
			);
		if (!username && callingEP
				&& FindAlias(callingEP->GetAliases(), username) == P_MAX_INDEX)
			username = PString::Empty();
	}

	if (username.IsEmpty() && hasCall) {
		username = GetBestAliasAddressString(
			authData.m_call->GetSourceAddress(), true,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));
		if (!username && callingEP
				&& FindAlias(callingEP->GetAliases(), username) == P_MAX_INDEX)
			username = PString::Empty();
	}

	if (username.IsEmpty() && callingEP)
		username = GetBestAliasAddressString(callingEP->GetAliases(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (username.IsEmpty() && hasCall)
		username = GetBestAliasAddressString(
			authData.m_call->GetSourceAddress(), false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (username.IsEmpty() && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceAddress))
		username = GetBestAliasAddressString(setupBody.m_sourceAddress, false,
			AliasAddressTagMask(H225_AliasAddress::e_h323_ID),
			AliasAddressTagMask(H225_AliasAddress::e_email_ID)
				| AliasAddressTagMask(H225_AliasAddress::e_url_ID));

	if (username.IsEmpty())
		q931pdu.GetCallingPartyNumber(username);

	if (username.IsEmpty()) {
		PIPSocket::Address addr(0);
		WORD port = 0;
		bool addrValid = false;

		if (hasCall)
			addrValid = authData.m_call->GetSrcSignalAddr(addr, port) && addr.IsValid();

		if (!addrValid && setupBody.HasOptionalField(H225_Setup_UUIE::e_sourceCallSignalAddress) && setupBody.m_sourceCallSignalAddress.IsValid())
			addrValid = GetIPFromTransportAddr(setupBody.m_sourceCallSignalAddress, addr)
				&& addr.IsValid();

		if (!addrValid && callingEP)
			addrValid = GetIPFromTransportAddr(callingEP->GetCallSignalAddress(), addr)
				&& addr.IsValid();

		if (addrValid)
			username = addr.AsString();
	}

	return username;
}

PString GkAuthenticator::GetCallingStationId(
	/// RRQ message
	const RasPDU<H225_RegistrationRequest> & request,
	/// additional data
	RRQAuthData & /* authData */
	) const
{
    PString id;
    const H225_RegistrationRequest & rrq = request;
    if (rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
        id = GetBestAliasAddressString(rrq.m_terminalAlias, false,
			AliasAddressTagMask(H225_AliasAddress::e_dialedDigits)
				| AliasAddressTagMask(H225_AliasAddress::e_partyNumber));
    };
    return id;
}

PString GkAuthenticator::GetCallingStationId(
	/// ARQ message with additional data
	const RasPDU<H225_AdmissionRequest> & /*request*/,
	/// additional data
	ARQAuthData & authData
	) const
{
	return authData.m_callingStationId;
}

PString GkAuthenticator::GetCallingStationId(
	const SetupMsg & /*setup*/,
	/// additional data
	SetupAuthData & authData
	) const
{
	return authData.m_callingStationId;
}

PString GkAuthenticator::GetCalledStationId(
	/// ARQ message with additional data
	const RasPDU<H225_AdmissionRequest> & /*request*/,
	/// additional data
	ARQAuthData & authData
	) const
{
	return authData.m_calledStationId;
}

PString GkAuthenticator::GetCalledStationId(
	const SetupMsg & /*setup*/,
	/// additional data
	SetupAuthData & authData
	) const
{
	return authData.m_calledStationId;
}

PString GkAuthenticator::GetDialedNumber(
	/// ARQ message with additional data
	const RasPDU<H225_AdmissionRequest> & /*request*/,
	/// additional data
	ARQAuthData & authData
	) const
{
	return authData.m_dialedNumber;
}

PString GkAuthenticator::GetDialedNumber(
	const SetupMsg & /*setup*/,
	/// additional data
	SetupAuthData & authData
	) const
{
	return authData.m_dialedNumber;
}

PString GkAuthenticator::GetInfo()
{
	return "No information available\r\n";
}

PString GkAuthenticator::ReplaceAuthParams(
	/// parametrized string
	const PString & str,
	/// parameter values
	const std::map<PString, PString> & params
	)
{
	PString finalStr((const char*)str);
	PINDEX len = finalStr.GetLength();
	PINDEX pos = 0;

	while (pos != P_MAX_INDEX && pos < len) {
		pos = finalStr.Find('%', pos);
		if (pos == P_MAX_INDEX || pos++ == P_MAX_INDEX)
			break;

		if (pos >= len) // strings ending with '%' - special case
			break;
		const char c = finalStr[pos]; // char next after '%'
		if (c == '%') { // replace %% with %
			finalStr.Delete(pos, 1);
			len--;
		} else if (c == '{') { // escaped syntax (%{Name})
			const PINDEX closingBrace = finalStr.Find('}', ++pos);
			if (closingBrace != P_MAX_INDEX) {
				const PINDEX paramLen = closingBrace - pos;
				std::map<PString, PString>::const_iterator i = params.find(finalStr.Mid(pos, paramLen));
				if (i != params.end()) {
					const PINDEX escapedLen = (i->second).GetLength();
					finalStr.Splice(i->second, pos - 2, paramLen + 3);
					len = len + escapedLen - paramLen - 3;
					pos = pos - 2 + escapedLen;
				} else {
				    // leave unknown placeholders intact so a 2nd stage can replace them
				}
			}
		} else { // simple syntax (%c)
			std::map<PString, PString>::const_iterator i = params.find(c);
			if (i != params.end()) {
				const PINDEX escapedLen = (i->second).GetLength();
				finalStr.Splice(i->second, pos - 1, 2);
				len = len + escapedLen - 2;
				pos = pos - 1 + escapedLen;
			} else {
                // leave unknown placeholders intact so a 2nd stage can replace them
			}
		}
	}

	return finalStr;
}


// class GkAuthenticatorList
GkAuthenticatorList::GkAuthenticatorList()
{
	// TODO: should we move this into OnReload() so it can be dynamically changed ?
	PFactory<H235Authenticator>::KeyList_T keyList = PFactory<H235Authenticator>::GetKeyList();
	PFactory<H235Authenticator>::KeyList_T::const_iterator r;

	// if a global list of autenticators is configured, use it in the priority order supplied
	PStringList authlist = Toolkit::Instance()->GetAuthenticatorList();
	if (authlist.GetSize() > 0) {
		for (PINDEX i = 0; i < authlist.GetSize(); ++i) {
			for (r = keyList.begin(); r != keyList.end(); ++r) {
				H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
				if (Auth && (PCaselessString(Auth->GetName()) == authlist[i])) {
					m_h235authenticators.Append(Auth);
				} else {
					delete Auth;
				}
			}
		}
	} else {
		for (r = keyList.begin(); r != keyList.end(); ++r) {
			H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
			if (Auth) {
				if ((Auth->GetApplication() == H235Authenticator::EPAuthentication)
					||(Auth->GetApplication() == H235Authenticator::GKAdmission)
					||(Auth->GetApplication() == H235Authenticator::AnyApplication) ) {
					m_h235authenticators.Append(Auth);
				} else {
					delete Auth;
				}
			}
		}
	}
}

GkAuthenticatorList::~GkAuthenticatorList()
{
	WriteLock lock(m_reloadMutex);
	DeleteObjectsInContainer(m_authenticators);
	m_authenticators.clear();
}

void GkAuthenticatorList::OnReload()
{
	// lock here to prevent too early authenticator destruction
	// from another thread
	WriteLock lock(m_reloadMutex);

	// first destroy old authenticators
	DeleteObjectsInContainer(m_authenticators);
	m_authenticators.clear();

	std::list<GkAuthenticator*> authenticators;

	const PStringArray authRules = GkConfig()->GetKeys(GkAuthSectionName);
	for (PINDEX r = 0; r < authRules.GetSize(); r++) {
		GkAuthenticator * auth = Factory<GkAuthenticator>::Create(authRules[r]);
		if (auth) {
			authenticators.push_back(auth);
		}
	}

	m_authenticators = authenticators;
}

void GkAuthenticatorList::SelectH235Capability(
	const H225_GatekeeperRequest & grq,
	H225_GatekeeperConfirm & gcf)
{
	ReadLock lock(m_reloadMutex);

	if (m_authenticators.empty()) {
		return;
	}

	// if GRQ does not contain a list of authentication mechanisms simply return
	if (!(grq.HasOptionalField(H225_GatekeeperRequest::e_authenticationCapability)
			&& grq.HasOptionalField(H225_GatekeeperRequest::e_algorithmOIDs)
			&& grq.m_authenticationCapability.GetSize() > 0
			&& grq.m_algorithmOIDs.GetSize() > 0)) {
		return;
	}

	for (PINDEX auth = 0; auth < m_h235authenticators.GetSize(); auth++) {
		for (PINDEX cap = 0; cap < grq.m_authenticationCapability.GetSize(); cap++) {
			for (PINDEX alg = 0; alg < grq.m_algorithmOIDs.GetSize(); alg++) {
				if (m_h235authenticators[auth].IsCapability(grq.m_authenticationCapability[cap], grq.m_algorithmOIDs[alg])) {
					std::list<GkAuthenticator*>::const_iterator iter = m_authenticators.begin();
					while (iter != m_authenticators.end()) {
						GkAuthenticator* gkauth = *iter++;
						if (gkauth->IsH235Capable() && gkauth->IsH235Capability(grq.m_authenticationCapability[cap], grq.m_algorithmOIDs[alg])) {
							PTRACE(4, "GKAUTH\tGRQ accepted on " << H323TransportAddress(gcf.m_rasAddress)
								<< " using authenticator " << m_h235authenticators[auth]);
                            // TODO: return authenticator or put it into tmp EPRec if we want to add tokens to GCF
							gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_authenticationMode);
							gcf.m_authenticationMode = grq.m_authenticationCapability[cap];
							gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_algorithmOID);
							gcf.m_algorithmOID = grq.m_algorithmOIDs[alg];
							if (gcf.m_authenticationMode.GetTag() == H235_AuthenticationMechanism::e_pwdSymEnc) {
								// add the challenge token
								gcf.IncludeOptionalField(H225_GatekeeperConfirm::e_tokens);
								// make sure we don't overwrite other tokens, eg. H.235.TSSM
								gcf.m_tokens.SetSize(gcf.m_tokens.GetSize() + 1);
								gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_tokenOID = "0.0";
								gcf.m_tokens[gcf.m_tokens.GetSize() - 1].IncludeOptionalField(H235_ClearToken::e_timeStamp);
								gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_timeStamp = (int)time(NULL); // Avaya seems to send a different timestamp that is 34 years back, but accpets this as well
								gcf.m_tokens[gcf.m_tokens.GetSize() - 1].IncludeOptionalField(H235_ClearToken::e_random);
#ifdef PSSL
                                // if we have OpenSSL, use it for random number generation, fall back on stdlib rand()
                                if(RAND_bytes(gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_random, sizeof(gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_random)) != 1) {
                                    gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_random = rand();
                                }
#else
								gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_random = rand();
#endif // PSSL
								gcf.m_tokens[gcf.m_tokens.GetSize() - 1].IncludeOptionalField(H235_ClearToken::e_generalID);
								gcf.m_tokens[gcf.m_tokens.GetSize() - 1].m_generalID = Toolkit::GKName();
							}
							return;
						}
					}
				}
			}
		}
	}
}

bool GkAuthenticatorList::Validate(
	/// RRQ to be validated by authenticators
	RasPDU<H225_RegistrationRequest> & request,
	/// authorization data (reject reason, ...)
	RRQAuthData & authData
	)
{
	ReadLock lock(m_reloadMutex);
	std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
	while (i != m_authenticators.end()) {
		GkAuthenticator* auth = *i++;
		if (auth->IsRasCheckEnabled(RasInfo<H225_RegistrationRequest>::flag)) {
			const int result = auth->Check(request, authData);
			if (result == GkAuthenticator::e_ok) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " RRQ check ok");
				if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
						|| auth->GetControlFlag() == GkAuthenticator::e_Alternative)
					return true;
			} else if (result == GkAuthenticator::e_fail) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " RRQ check failed");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " RRQ check failed");
				return false;
			}
		}
	}
	return true;
}

bool GkAuthenticatorList::Validate(
	/// ARQ to be validated by authenticators
	RasPDU<H225_AdmissionRequest> & request,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & authData)
{
	ReadLock lock(m_reloadMutex);
	std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
	while (i != m_authenticators.end()) {
		GkAuthenticator* auth = *i++;
		if (auth->IsRasCheckEnabled(RasInfo<H225_AdmissionRequest>::flag)) {
			const long oldDurationLimit = authData.m_callDurationLimit;
			const int result = auth->Check(request, authData);
			if (authData.m_callDurationLimit == 0) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " ARQ check failed: "
					"call duration 0");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " ARQ check failed");
				return false;
			}
			if (authData.m_callDurationLimit >= 0 && oldDurationLimit >= 0)
				authData.m_callDurationLimit = PMIN(
					authData.m_callDurationLimit, oldDurationLimit
					);
			else
				authData.m_callDurationLimit = PMAX(
					authData.m_callDurationLimit, oldDurationLimit
					);
			if (result == GkAuthenticator::e_ok) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " ARQ check ok");
				if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
						|| auth->GetControlFlag() == GkAuthenticator::e_Alternative)
					return true;
			} else if (result == GkAuthenticator::e_fail) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " ARQ check failed");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " ARQ check failed");
				return false;
			}
		}
	}
	return true;
}

bool GkAuthenticatorList::Validate(
	SetupMsg & setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & authData)
{
	ReadLock lock(m_reloadMutex);
	std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
	while (i != m_authenticators.end()) {
		GkAuthenticator* auth = *i++;
		if (auth->IsMiscCheckEnabled(GkAuthenticator::e_Setup)
			|| (!authData.m_fromRegistered
				&& auth->IsMiscCheckEnabled(GkAuthenticator::e_SetupUnreg))) {
			const long oldDurationLimit = authData.m_callDurationLimit;
			const int result = auth->Check(setup, authData);
			if (authData.m_callDurationLimit == 0) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " Setup check failed: "
					"call duration limit 0");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " Setup check failed");
				return false;
			}
			if (authData.m_callDurationLimit >= 0 && oldDurationLimit >= 0) {
				authData.m_callDurationLimit = PMIN(authData.m_callDurationLimit, oldDurationLimit);
			} else {
				authData.m_callDurationLimit = PMAX(authData.m_callDurationLimit, oldDurationLimit);
			}
			if (result == GkAuthenticator::e_ok) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " Setup check ok");
				if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
						|| auth->GetControlFlag() == GkAuthenticator::e_Alternative)
					return true;
			} else if (result == GkAuthenticator::e_fail) {
				PTRACE(3, "GKAUTH\t" << auth->GetName() << " Setup check failed");
				SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " Setup check failed");
				return false;
			}
		}
	}
	return true;
}

bool GkAuthenticatorList::Validate(Q931 & msg, Q931AuthData & authData)
{
	ReadLock lock(m_reloadMutex);
	std::list<GkAuthenticator*>::const_iterator i = m_authenticators.begin();
	while (i != m_authenticators.end()) {
		GkAuthenticator* auth = *i++;
		if (auth->IsMiscCheckEnabled(auth->AuthEnum(msg.GetMessageType()))) {
            const int result = auth->Check(msg, authData);
            if (result == GkAuthenticator::e_ok) {
                PTRACE(3, "GKAUTH\t" << auth->GetName() << " Q931 check ok");
                if (auth->GetControlFlag() == GkAuthenticator::e_Sufficient
                        || auth->GetControlFlag() == GkAuthenticator::e_Alternative)
                    return true;
            } else if (result == GkAuthenticator::e_fail) {
                PTRACE(3, "GKAUTH\t" << auth->GetName() << " Q931 check failed");
                SNMP_TRAP(8, SNMPError, Authentication, auth->GetName() + " Q931 check failed");
                return false;
            }
        }
	}
	return true;
}

// class CacheManager
bool CacheManager::Retrieve(
	const PString & key, /// the key to look for
	PString & value /// filled with the value on return
	) const
{
	// quick check
	if (m_ttl == 0)
		return false;

	ReadLock lock(m_rwmutex);

	std::map<PString, PString>::const_iterator iter = m_cache.find(key);
	if (iter == m_cache.end())
		return false;
	if (m_ttl >= 0) {
		std::map<PString, time_t>::const_iterator i = m_ctime.find(key);
		if (i == m_ctime.end() || (time(NULL) - i->second) >= m_ttl)
			return false; // cache expired
	}
	value = (const char *)(iter->second);
	return true;
}

void CacheManager::Save(
	const PString & key, /// a key to be stored
	const PString & value /// a value to be associated with the key
	)
{
	if (m_ttl != 0) {
		WriteLock lock(m_rwmutex);
		m_cache[key] = (const char*)value;
		m_ctime[key] = time(NULL);
	}
}


// class SimplePasswordAuth
SimplePasswordAuth::SimplePasswordAuth(
	const char * name,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks), m_cache(NULL)
{
	if (!GetConfig()->HasKey(name, "KeyFilled")) {
        // TODO: remove this warning when subclassed and passwords aren't encrypted (eg. with SQLPasswordAuth, HttpPasswordAuth or LuaPasswordAuth)
		PTRACE(1, "GKAUTH\t" << GetName() << " KeyFilled config variable is missing");
	}
	m_encryptionKey = GetConfig()->GetInteger(name, "KeyFilled", 0);
	m_checkID = GkConfig()->GetBoolean("H235", "CheckSendersID", true);
	if (GkConfig()->HasKey(name, "CheckID")) {
        m_checkID = GkConfig()->GetBoolean(name, "CheckID", true);  // backward compatibility, deprecated
	}
	m_cache = new CacheManager(GetConfig()->GetInteger(name, "PasswordTimeout", -1));
	m_disabledAlgorithms = GetConfig()->GetString(name, "DisableAlgorithm", "").Tokenise(",;", FALSE);

    PFactory<H235Authenticator>::KeyList_T keyList = PFactory<H235Authenticator>::GetKeyList();
    PFactory<H235Authenticator>::KeyList_T::const_iterator r;

	PStringList authlist = Toolkit::Instance()->GetAuthenticatorList();
	// if a global list of autenticators is configured, use it in the priority order supplied
	if (authlist.GetSize() > 0) {
		for (PINDEX i = 0; i < authlist.GetSize(); ++i) {
			for (r = keyList.begin(); r != keyList.end(); ++r) {
				H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
				// only use, if it's not disabled for this GnuGk authentication method
				if (Auth && (PCaselessString(Auth->GetName()) == authlist[i])
					&& (m_disabledAlgorithms.GetStringsIndex(Auth->GetName()) == P_MAX_INDEX)) {
					if ((Auth->GetApplication() == H235Authenticator::EPAuthentication)
						||(Auth->GetApplication() == H235Authenticator::GKAdmission)
						||(Auth->GetApplication() == H235Authenticator::AnyApplication) ) {
						AppendH235Authenticator(Auth);
					} else {
						delete Auth;
					}
				}
			}
		}
	} else {
		for (r = keyList.begin(); r != keyList.end(); ++r) {
			H235Authenticator * Auth = PFactory<H235Authenticator>::CreateInstance(*r);
			// only use, if it's not disabled for this GnuGk authentication method
			if (Auth && (m_disabledAlgorithms.GetStringsIndex(Auth->GetName()) == P_MAX_INDEX)) {
				if ((Auth->GetApplication() == H235Authenticator::EPAuthentication)
					||(Auth->GetApplication() == H235Authenticator::GKAdmission)
					||(Auth->GetApplication() == H235Authenticator::AnyApplication) ) {
					AppendH235Authenticator(Auth);
				} else {
					delete Auth;
				}
			}
		}
	}
}

SimplePasswordAuth::~SimplePasswordAuth()
{
	delete m_cache;
}

int SimplePasswordAuth::Check(
	RasPDU<H225_RegistrationRequest> & request,
	RRQAuthData & authData)
{
	H225_RegistrationRequest & rrq = request;
	GkH235Authenticators * auth = NULL;
	int result = doCheck(request, rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias) ? &rrq.m_terminalAlias : NULL, auth);
    authData.m_authenticator = auth;    // save auth
    return result;
}

int SimplePasswordAuth::Check(RasPDU<H225_UnregistrationRequest> & request, unsigned &)
{
    H225_UnregistrationRequest & urq = request;
    H225_ArrayOf_AliasAddress aliases;
	GkH235Authenticators * auth = NULL;
    if (urq.HasOptionalField(H225_UnregistrationRequest::e_endpointIdentifier)) {
        endptr ep = RegistrationTable::Instance()->FindByEndpointId(urq.m_endpointIdentifier);
        if (ep) {
            aliases = ep->GetAliases();
            auth = ep->GetH235Authenticators();
        }
    }

    if (aliases.GetSize() > 0) {
        return doCheck(request, &aliases, auth);
    } else {
        return doCheck(request, NULL, auth); // can't check sendersID
    }
}

int SimplePasswordAuth::Check(RasPDU<H225_BandwidthRequest> & request, unsigned &)
{
    H225_BandwidthRequest & brq = request;
    endptr ep = RegistrationTable::Instance()->FindByEndpointId(brq.m_endpointIdentifier);
    if (ep) {
        H225_ArrayOf_AliasAddress aliases = ep->GetAliases();
        GkH235Authenticators * auth = ep->GetH235Authenticators();
        return doCheck(request, &aliases, auth);
    } else {
        return e_fail;
    }
}

int SimplePasswordAuth::Check(RasPDU<H225_DisengageRequest> & request, unsigned &)
{
    H225_DisengageRequest & drq = request;
    endptr ep = RegistrationTable::Instance()->FindByEndpointId(drq.m_endpointIdentifier);
    if (ep) {
        H225_ArrayOf_AliasAddress aliases = ep->GetAliases();
        GkH235Authenticators * auth = ep->GetH235Authenticators();
        return doCheck(request, &aliases, auth);
    } else {
        return e_fail;
    }
}

int SimplePasswordAuth::Check(RasPDU<H225_LocationRequest> & request, unsigned &)
{
	GkH235Authenticators * auth = NULL;
	return doCheck(request, NULL, auth);
}

int SimplePasswordAuth::Check(RasPDU<H225_InfoRequest> & request, unsigned &)
{
	GkH235Authenticators * auth = NULL;
	return doCheck(request, NULL, auth);
}

int SimplePasswordAuth::Check(RasPDU<H225_ResourcesAvailableIndicate> & request, unsigned &)
{
    H225_ResourcesAvailableIndicate & rai = request;
    endptr ep = RegistrationTable::Instance()->FindByEndpointId(rai.m_endpointIdentifier);
    if (ep) {
        H225_ArrayOf_AliasAddress aliases = ep->GetAliases();
        GkH235Authenticators * auth = ep->GetH235Authenticators();
        return doCheck(request, &aliases, auth);
    } else {
        return e_fail;
    }
}

int SimplePasswordAuth::Check(
	/// ARQ to be authenticated/authorized
	RasPDU<H225_AdmissionRequest> & request,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & authData)
{
	// use the aliases from the registration; some endpoints (eg. Innovaphone myPBX) send empty srcInfo
	if (authData.m_requestingEP) {
        H225_ArrayOf_AliasAddress aliases = authData.m_requestingEP->GetAliases();
        GkH235Authenticators * auth = authData.m_requestingEP->GetH235Authenticators();
        return doCheck(request, &aliases, auth);
    } else {
        return e_fail;
    }
}

int SimplePasswordAuth::Check(
	/// Q.931 message to be authenticated/authorized
	Q931 & msg,
	/// authorization data
	Q931AuthData & authData)
{
	return doCheck(msg, authData);
}


bool SimplePasswordAuth::GetPassword(
	const PString & id, /// get the password for this id
	PString & passwd, /// filled with the password on return
    std::map<PString, PString> & params /// map of authentication parameters
)
{
	if (id.IsEmpty())
		return false;
	if (!GetConfig()->HasKey(GetName(), id))
		return false;
    // make sure the alias name is not one of the switches allowed in the SimplePasswordAuth section
	if (strcasecmp(id, "KeyFilled") == 0
        || strcasecmp(id, "CheckID") == 0
        || strcasecmp(id, "DisableAlgorithm") == 0
		|| strcasecmp(id, "PasswordTimeout") == 0) {
		PTRACE(2, "GKAUTH\t" << GetName() << " trying to get password for the forbidden alias '" << id << '\'');
		return false;
	}
	passwd = Toolkit::Instance()->ReadPassword(GetName(), id, true);
	return true;
}

bool SimplePasswordAuth::InternalGetPassword(
	const PString & id, /// get the password for this id
	PString & passwd, /// filled with the password on return
    std::map<PString, PString> & params /// map of authentication parameters
	)
{
    params["u"] = id;

	if (m_cache->Retrieve(id, passwd)) {
		PTRACE(5, "GKAUTH\t" << GetName() << " cached password found for '" << id << '\'');
		return true;
	}
	if (GetPassword(id, passwd, params)) {
		m_cache->Save(id, passwd);
		return true;
	} else
		return false;
}

int SimplePasswordAuth::CheckTokens(
	GkH235Authenticators * & authenticators,
	/// an array of tokens to be checked
	const H225_ArrayOf_ClearToken & tokens,
	/// aliases for the endpoint that generated the tokens
	const H225_ArrayOf_AliasAddress * aliases,
    /// map of authentication parameters
    std::map<PString, PString> & params
    )
{
	for (PINDEX i = 0; i < tokens.GetSize(); i++) {
		H235_ClearToken & token = tokens[i];

		// check for Cisco Access Token
		if (token.m_tokenOID == OID_H235_CAT) {
			if (authenticators == NULL)
				authenticators = new GkH235Authenticators;

			if (!token.HasOptionalField(H235_ClearToken::e_generalID)) {
				PTRACE(3, "GKAUTH\t" << GetName() << " generalID field not found inside CAT token");
				return e_fail;
			}
			const PString id = token.m_generalID;
			if (m_checkID && (aliases == NULL || FindAlias(*aliases, id) == P_MAX_INDEX)) {
				PTRACE(3, "GKAUTH\t" << GetName() << " generalID '" << id
					<< "' of CAT token does not match any alias for the endpoint");
				return e_fail;
			}

			if (authenticators->HasCATPassword())
				return e_ok;

			PString passwd;
			if (!InternalGetPassword(id, passwd, params)) {
				PTRACE(3, "GKAUTH\t" << GetName() << " password not found for '" << id << '\'');
				return e_fail;
			}
			authenticators->SetCATData(id, passwd);

			return e_ok;
		}
	}
	return e_next;
}

int SimplePasswordAuth::CheckCryptoTokens(
	GkH235Authenticators * & authenticators,
	/// an array of cryptoTokens to be checked
	const H225_ArrayOf_CryptoH323Token & tokens,
	/// aliases for the endpoint that generated the tokens
	const H225_ArrayOf_AliasAddress * aliases,
	/// allow any sendersID (eg. in RRQ)
	bool acceptAnySendersID,
    /// map of authentication parameters
    std::map<PString, PString> & params
	)
{
	for (PINDEX i = 0; i < tokens.GetSize(); i++) {
		if (tokens[i].GetTag() == H225_CryptoH323Token::e_cryptoEPPwdHash) {
			if (authenticators == NULL)
				authenticators = new GkH235Authenticators;

			H225_CryptoH323Token_cryptoEPPwdHash & pwdhash = tokens[i];
			const PString id = AsString(pwdhash.m_alias, false);
			if (m_checkID && (aliases == NULL || FindAlias(*aliases, id) == P_MAX_INDEX)) {
				PTRACE(3, "GKAUTH\t" << GetName() << " alias '" << id
					<< "' of the cryptoEPPwdHash token does not match any alias for the endpoint");
				return e_fail;
			}

			if (authenticators->HasMD5Password())
				return e_ok;

			PString passwd;
			if (!InternalGetPassword(id, passwd, params)) {
				PTRACE(3, "GKAUTH\t" << GetName() << " password not found for '" << id << '\'');
				return e_fail;
			}

			authenticators->SetSimpleMD5Data(id, passwd);
#if P_SSL
		} else if (tokens[i].GetTag() == H225_CryptoH323Token::e_nestedcryptoToken) {
			const H235_CryptoToken & nestedCryptoToken = tokens[i];

			if (nestedCryptoToken.GetTag() != H235_CryptoToken::e_cryptoHashedToken)
				continue;

			const H235_CryptoToken_cryptoHashedToken & cryptoHashedToken = nestedCryptoToken;
			if (cryptoHashedToken.m_tokenOID != OID_H235_A_V1
					&& cryptoHashedToken.m_tokenOID != OID_H235_A_V2)
				continue;

			if (authenticators == NULL && acceptAnySendersID) {
				authenticators = new GkH235Authenticators;  // allocate a new authenticator, eg. for RRQ and LRQ where we don't have an existing EPRec
            }
			if (authenticators == NULL)
                continue;   // can't validate this token without authenticator object

			const H235_ClearToken & clearToken = cryptoHashedToken.m_hashedVals;
			PString sendersID;
			bool hasSendersId = clearToken.HasOptionalField(H235_ClearToken::e_sendersID);
			if (!hasSendersId) {
                if (m_checkID) {
                    PTRACE(5, "GKAUTH\t" << GetName() << " hashedVals of nested cryptoHashedToken do not contain sendersID");
                    continue;   // ignore token
                }
			} else {
			    sendersID = clearToken.m_sendersID;
			}

            // verify correct value of sendersID (avoid replay attack)
            // must be either the endpointID or one of the aliasses
			H225_EndpointIdentifier epId;
			epId = sendersID;
            endptr ep = RegistrationTable::Instance()->FindByEndpointId(epId);  // check if sendersID is the endpointID
            if (m_checkID  && !acceptAnySendersID) {
                PBoolean sendersIDValid = ep || (aliases != NULL && FindAlias(*aliases, sendersID) != P_MAX_INDEX);
                if (!sendersIDValid) {
                    PTRACE(5, "GKAUTH\t" << GetName() << " sendersID does not match endpointID nor an alias");
                    continue;   // ignore token
                }
            }

            PBoolean requireGeneralID = m_config->GetBoolean("H235", "RequireGeneralID", false);
            if (requireGeneralID) {
                if (!clearToken.HasOptionalField(H235_ClearToken::e_generalID)) {
                    PTRACE(5, "GKAUTH\t" << GetName() << " hashedVals of nested cryptoHashedToken do not contain generalID");
                    continue;   // ignore token
                }
            }

			if (authenticators->HasProcedure1Password()) {
                return e_ok;
			}

            // lookup password
			PString passwd;
            bool passwordFound = InternalGetPassword(sendersID, passwd, params); // check if we have a password for sendersID first

			if (passwordFound) {
                PTRACE(3, "GKAUTH\t" << GetName() << " Authenticating user " << sendersID);
            }

            // try endpoint aliases
            if (!passwordFound) {
				H225_ArrayOf_AliasAddress epAliases;
                if (ep) {
                    // if we have the EndpointRec use the aliases from there
                    epAliases = ep->GetAliases();
                } else if (aliases) {
                    // if not (eg. for RRQ) use the aliases from the message
                    epAliases = *aliases;
                }
				// check all endpoint aliases for a password
				for (PINDEX i = 0; i < epAliases.GetSize(); i++) {
					PString id = H323GetAliasAddressString(epAliases[i]);
					passwordFound = InternalGetPassword(id, passwd, params);
					if (passwordFound) {
                        PTRACE(3, "GKAUTH\t" << GetName() << " Authenticating user " << id);
                        // TODO235: set sendersID = id so the right id is set for H323Plus authenticator ????
						break;
					}
				}
            }

			if (!passwordFound) {
				PTRACE(3, "GKAUTH\t" << GetName() << " password not found for '" << sendersID << '\'');
				return e_fail;
			}

			authenticators->SetProcedure1Data(Toolkit::GKName(), sendersID, passwd, requireGeneralID);
#endif
		} else if (tokens[i].GetTag() == H225_CryptoH323Token::e_cryptoEPPwdEncr) {
			if (authenticators == NULL)
				authenticators = new GkH235Authenticators;

			if (aliases == NULL) {
				PTRACE(3, "GKAUTH\t" << GetName() << " need a user alias to authenticate");
				return e_fail;
			}

#ifdef HAS_DES_ECB
			if (authenticators->HasDESPassword())
				return e_ok;
#endif

			PString id, passwd;
			for (PINDEX j = 0; j < aliases->GetSize(); j++) {
                // check if we have a password for one of the aliases
                if (InternalGetPassword(AsString(aliases[j], false), passwd, params)) {
                    id = AsString(aliases[j], false);
                    break;
                }
			}
			if (passwd.IsEmpty()) {
				PTRACE(3, "GKAUTH\t" << GetName() << " no password found for any alias '" << AsString(*aliases, false));
				return e_fail;
			}

#ifdef HAS_DES_ECB
			authenticators->SetDESData(id, passwd);
#endif
		}
	}
	return e_next;
}


#ifdef H323_H350

H350PasswordAuth::H350PasswordAuth(const char* authName) : SimplePasswordAuth(authName)
{
}

H350PasswordAuth::~H350PasswordAuth()
{
}

bool H350PasswordAuth::GetPassword(const PString & alias, PString & password, std::map<PString, PString> & params)
{
	// search the directory
	PString search = GkConfig()->GetString(H350Section, "SearchBaseDN", "");

	H225_AliasAddress aliasaddress;
	H323SetAliasAddress(alias, aliasaddress);

	PString filter = "h235IdentityEndpointID=" + alias;

	H350_Session session;
	if (!Toolkit::Instance()->CreateH350Session(&session)) {
		PTRACE(1, "H350\tH235Auth: Could not connect to server");
		return false;
	}

	H350_Session::LDAP_RecordList rec;
	int count = session.Search(search, filter, rec);
	if (count <= 0) {
		PTRACE(4, "H350\tH235Auth: No record found");
		session.Close();
		return false;
	}

	// locate the record
	for (H350_Session::LDAP_RecordList::const_iterator x = rec.begin(); x != rec.end(); ++x) {
		H350_Session::LDAP_Record entry = x->second;
		if (session.GetAttribute(entry, "h235IdentityPassword", password)) {
			password = password.Trim();	// server may send newline at end etc.
			PTRACE(4, "H350\tH235Auth: Password located");
			session.Close();
			return true;
		}
	}

	PTRACE(4, "H350\tH235Auth: No password found");
	session.Close();
	return false;
}

#endif // H323_H350


// class AliasAuth
AliasAuth::AliasAuth(
	const char * name,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks), m_cache(NULL)
{
	m_cache = new CacheManager(GetConfig()->GetInteger(name, "CacheTimeout", -1));
}

AliasAuth::~AliasAuth()
{
	delete m_cache;
}

int AliasAuth::Check(
	RasPDU<H225_RegistrationRequest> & request,
	RRQAuthData & /*authData*/)
{
	H225_RegistrationRequest & rrq = request;

	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
		PTRACE(3, "GKAUTH\t" << GetName() << " - terminalAlias field not found in RRQ message");
		return GetDefaultStatus();
	}

	const H225_ArrayOf_AliasAddress & aliases = rrq.m_terminalAlias;

    // NOTE: run loop 1 round more than we have aliases to check "default" rule
	for (PINDEX i = 0; i <= aliases.GetSize(); i++) {
		const PString alias = (i < aliases.GetSize()) ? AsString(aliases[i], false) : PString("default");
		PString authcond;
		if (InternalGetAuthConditionString(alias, authcond)) {
			bool checkPort = true;
			// don't check the signaling port if the endpoint uses H.460.18
#ifdef HAS_H46018
			if (rrq.HasOptionalField(H225_RegistrationRequest::e_featureSet)) {
				H460_FeatureSet fs = H460_FeatureSet(rrq.m_featureSet);
				if (fs.HasFeature(18) && Toolkit::Instance()->IsH46018Enabled()) {
					checkPort = false;
				}
			}
#endif
			if (doCheck(rrq.m_callSignalAddress, authcond, checkPort)) {
				PTRACE(5, "GKAUTH\t" << GetName() << " auth condition '"
					<< authcond <<"' accepted RRQ from '" << alias << '\'');
				return e_ok;
			} else {
				PTRACE(3, "GKAUTH\t" << GetName() << " auth condition '"
					<< authcond <<"' rejected RRQ from '" << alias << '\'');
				return e_fail;
			}
		} else
			PTRACE(4, "GKAUTH\t" << GetName() << " auth condition not found for alias '" << alias << '\'');
	}
	return GetDefaultStatus();
}

bool AliasAuth::GetAuthConditionString(
	/// an alias the condition string is to be retrieved for
	const PString & alias,
	/// filled with auth condition string that has been found
	PString & authCond)
{
	if (alias.IsEmpty())
		return false;
	if (!GetConfig()->HasKey("RasSrv::RRQAuth", alias))
		return false;
	if (strcasecmp(alias, "CacheTimeout") == 0) {
		PTRACE(2, "GKAUTH\t" << GetName() << " trying to get auth condition "
			" string for the forbidden alias '" << alias << '\'');
		return false;
	}
	authCond = GetConfig()->GetString("RasSrv::RRQAuth", alias, "");
	return true;
}

bool AliasAuth::InternalGetAuthConditionString(
	const PString & id, /// get the password for this id
	PString & authCond /// filled with the auth condition string on return
	)
{
	if (m_cache->Retrieve(id, authCond)) {
		PTRACE(5, "GKAUTH\t" << GetName() << " cached auth condition string found for '" << id << '\'');
		return true;
	}
	if (GetAuthConditionString(id, authCond)) {
		m_cache->Save(id, authCond);
		return true;
	} else
		return false;
}

bool AliasAuth::doCheck(
	/// an array of source signaling addresses for an endpoint that sent the request
	const H225_ArrayOf_TransportAddress & sigaddr,
	/// auth condition string as returned by GetAuthConditionString
	const PString & condition,
	bool checkPort)
{
	const PStringArray authrules(condition.Tokenise("&|", FALSE));
	if (authrules.GetSize() < 1) {
		PTRACE(2, "GKAUTH\t" << GetName() << " contains an empty auth condition");
		return false;
	}
	for (PINDEX i = 0; i < authrules.GetSize(); ++i) {
		for (PINDEX j = 0; j < sigaddr.GetSize(); ++j) {
			if (CheckAuthRule(sigaddr[j], authrules[i], checkPort)) {
				PTRACE(5, "GKAUTH\t" << GetName() << " auth rule '"
					<< authrules[i] << "' applied successfully to RRQ "
					" from " << AsDotString(sigaddr[j]));
				return true;
			}
		}
	}
	return false;
}

bool AliasAuth::CheckAuthRule(
	/// a signaling address for the endpoint that sent the request
	const H225_TransportAddress & sigaddr,
	/// the auth rule to be used for checking
	const PString & authrule,
	bool checkPort)
{
	PStringArray rule = authrule.Tokenise(":", false);
	if (rule.GetSize() < 1) {
		PTRACE(1, "GKAUTH\t" << GetName() << " found invalid empty auth rule '" << authrule << '\'');
		return false;
	}

	// authrule = rName[:params...]
	const PString rName = rule[0].Trim();

 	if (strcasecmp(rName, "confirm") == 0 || strcasecmp(rName, "allow") == 0)
 		return true;
 	else if (strcasecmp(rName, "reject") == 0 || strcasecmp(rName, "deny") == 0
		|| strcasecmp(rName, "forbid") == 0)
 		return false;
	else if (strcasecmp(rName, "sigaddr") == 0) {
		// condition 'sigaddr' example:
		//   sigaddr:.*ipAddress .* ip = .* c3 47 e2 a2 .*port = 1720.*
		if (rule.GetSize() < 2) {
			PTRACE(1, "GKAUTH\t" << GetName() << " found invalid empty sigaddr "
				"auth rule '" << authrule << '\'');
			return false;
		}
		// ignore port for H.460.18
		if (!checkPort && rule[1].Find("port") != P_MAX_INDEX) {
			rule[1] = rule[1].Left(rule[1].Find("port"));
		}
		return Toolkit::MatchRegex(AsString(sigaddr), rule[1].Trim()) != 0;
	} else if (strcasecmp(rName, "sigip") == 0) {
		// condition 'sigip' example:
		//   sigip:195.71.129.69:1720
		if (rule.GetSize() < 2) {
			PTRACE(1, "GKAUTH\t" << GetName() << " found invalid empty sigip "
				"auth rule '" << authrule << '\'');
			return false;
		}
		PString allowed_ip = authrule.Mid(authrule.Find("sigip:")+6).Trim();
		PStringArray ip_parts = SplitIPAndPort(allowed_ip, GK_DEF_ENDPOINT_SIGNAL_PORT);
		PIPSocket::Address ip;
		PIPSocket::GetHostAddress(ip_parts[0], ip);
		WORD port = (WORD)(ip_parts[1].AsUnsigned());
		// ignore port for H.460.18
		if (!checkPort) {
			PIPSocket::Address notUsed;
			WORD EPPort;
			GetIPAndPortFromTransportAddr(sigaddr, notUsed, EPPort);
			port = EPPort;
		}
		return (sigaddr == SocketToH225TransportAddr(ip, port));
	} else {
		PTRACE(1, "GKAUTH\t" << GetName() << " found unknown auth rule '" << rName << '\'');
		return false;
	}
}

// class PrefixAuth

class AuthRule;
class AuthObj;

class PrefixAuth : public GkAuthenticator
{
public:
	typedef std::map< PString, AuthRule *, greater<PString> > Rules;

	enum SupportedRasChecks {
		PrefixAuthRasChecks = RasInfo<H225_AdmissionRequest>::flag
			| RasInfo<H225_LocationRequest>::flag,
		PrefixAuthMiscChecks = e_Setup | e_SetupUnreg
	};

	PrefixAuth(
		const char* name,
		unsigned supportedRasChecks = PrefixAuthRasChecks,
		unsigned supportedMiscChecks = PrefixAuthMiscChecks);

	virtual ~PrefixAuth();

	// override from class GkAuthenticator
	virtual int Check(RasPDU<H225_LocationRequest> & request, unsigned & rejectReason);

	/** Authenticate/Authorize ARQ message. Override from GkAuthenticator.

	    @return
	    e_fail - authentication failed
	    e_ok - authenticated with this authenticator
	    e_next - authentication could not be determined
	*/
	virtual int Check(
		/// ARQ to be authenticated/authorized
		RasPDU<H225_AdmissionRequest> & request,
		/// authorization data (call duration limit, reject reason, ...)
		ARQAuthData & authData);

	/** Authenticate using data from Q.931 Setup message.

		@return:
		#GkAuthenticator::Status enum# with the result of authentication.
	*/
	virtual int Check(
		/// Q.931/H.225 Setup message to be authenticated
		SetupMsg & setup,
		/// authorization data (call duration limit, reject reason, ...)
		SetupAuthData & authData
		);

protected:
	virtual int doCheck(const AuthObj& aobj);

private:
	PrefixAuth();
	PrefixAuth(const PrefixAuth &);
	PrefixAuth & operator=(const PrefixAuth &);

private:
	Rules m_prefrules;
	int m_defaultRule;
};

// Help classes for PrefixAuth
class AuthObj // abstract class
{
public:
	virtual ~AuthObj() { }

	virtual bool IsValid() const { return true; }

	virtual PStringArray GetPrefixes() const = 0;

	virtual PIPSocket::Address GetIP() const = 0;
	virtual PString GetAliases() const = 0;
};

class ARQAuthObj : public AuthObj
{
public:
	ARQAuthObj(const H225_AdmissionRequest & arq);

	virtual bool IsValid() const { return m_ep; }

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	ARQAuthObj();
	ARQAuthObj(const ARQAuthObj &);
	ARQAuthObj & operator=(const ARQAuthObj &);

private:
	const H225_AdmissionRequest& m_arq;
	endptr m_ep;
};

class LRQAuthObj : public AuthObj
{
public:
	LRQAuthObj(const H225_LocationRequest & lrq);

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	LRQAuthObj();
	LRQAuthObj(const LRQAuthObj &);
	LRQAuthObj & operator=(const LRQAuthObj &);

private:
	const H225_LocationRequest & m_lrq;
	PIPSocket::Address m_ipAddress;
};

class SetupAuthObj : public AuthObj
{
public:
	SetupAuthObj(const SetupMsg & setup);

	virtual PStringArray GetPrefixes() const;

	virtual PIPSocket::Address GetIP() const;
	virtual PString GetAliases() const;

private:
	SetupAuthObj();
	SetupAuthObj(const SetupAuthObj &);
	SetupAuthObj & operator=(const SetupAuthObj &);

private:
	const SetupMsg & m_setup;
	PIPSocket::Address m_ipAddress;
};

class AuthRule : public NamedObject
{
public:
	enum Result {
		e_nomatch,
		e_allow,
		e_deny
	};

	AuthRule(
		Result fate,
		bool inverted
		) : m_priority(1000), m_fate(fate), m_inverted(inverted), m_next(NULL) { }

	virtual ~AuthRule() { delete m_next; }

	virtual bool Match(const AuthObj & aobj) = 0;

	int Check(const AuthObj & aobj);

	bool operator<(const AuthRule & obj) const { return m_priority < obj.m_priority; }

	void SetNext(AuthRule * next) { m_next = next; }

private:
	AuthRule();
	AuthRule(const AuthRule& );
	AuthRule & operator=(const AuthRule &);

protected:
	/// the lesser the value, the higher the priority
	int m_priority;

private:
	Result m_fate;
	bool m_inverted;
	AuthRule * m_next;
};

class NullRule : public AuthRule
{
public:
	NullRule() : AuthRule(e_nomatch, false) { SetName("NULL"); }

	virtual bool Match(const AuthObj & /*aobj*/) { return false; }

private:
	NullRule(const NullRule &);
	NullRule & operator=(const NullRule &);
};

class IPAuthRule : public AuthRule
{
public:
	IPAuthRule(Result fate, const PString & ipStr, bool inverted);

	virtual bool Match(const AuthObj & aobj);

private:
	IPAuthRule();
	IPAuthRule(const IPAuthRule &);
	IPAuthRule & operator=(const IPAuthRule &);

private:
	PIPSocket::Address m_network, m_netmask;
};

class AliasAuthRule : public AuthRule
{
public:
	AliasAuthRule(
		Result fate,
		const PString & aliasStr,
		bool inverted
		) : AuthRule(fate, inverted), m_pattern(aliasStr)
	{
		m_priority = -1;
		SetName(PString((fate == e_allow) ? "allow alias" : "deny alias")
			+ (inverted ? ":!" : ":") + aliasStr);
	}

	virtual bool Match(const AuthObj & aobj);

private:
	AliasAuthRule();
	AliasAuthRule(const AliasAuthRule &);
	AliasAuthRule & operator=(const AliasAuthRule &);

private:
	PString m_pattern;
};


ARQAuthObj::ARQAuthObj(const H225_AdmissionRequest & arq)
	: m_arq(arq), m_ep(RegistrationTable::Instance()->FindByEndpointId(arq.m_endpointIdentifier))
{
}

PStringArray ARQAuthObj::GetPrefixes() const
{
	PStringArray array;
	if (m_arq.HasOptionalField(H225_AdmissionRequest::e_destinationInfo)) {
		const PINDEX ss = m_arq.m_destinationInfo.GetSize();
		if (ss > 0) {
			array.SetSize(ss);
			for (PINDEX i = 0; i < ss; ++i)
				array[i] = AsString(m_arq.m_destinationInfo[i], false);
		}
	}
	if (array.GetSize() == 0)
		array.AppendString(PString::Empty());
	return array;
}

PIPSocket::Address ARQAuthObj::GetIP() const
{
	PIPSocket::Address result;
	const H225_TransportAddress & addr =
		m_arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress)
		? m_arq.m_srcCallSignalAddress : m_ep->GetCallSignalAddress();
	GetIPFromTransportAddr(addr, result);
	return result;
}

PString ARQAuthObj::GetAliases() const
{
	return AsString(m_ep->GetAliases());
}

LRQAuthObj::LRQAuthObj(const H225_LocationRequest & lrq)
	: m_lrq(lrq)
{
	GetIPFromTransportAddr(m_lrq.m_replyAddress, m_ipAddress);
}

PStringArray LRQAuthObj::GetPrefixes() const
{
	PStringArray array;
	const PINDEX ss = m_lrq.m_destinationInfo.GetSize();
	if (ss > 0) {
		array.SetSize(ss);
		for (PINDEX i = 0; i < ss; ++i)
			array[i] = AsString(m_lrq.m_destinationInfo[i], false);
	}
	return array;
}

PIPSocket::Address LRQAuthObj::GetIP() const
{
	return m_ipAddress;
}

PString LRQAuthObj::GetAliases() const
{
	return m_lrq.HasOptionalField(H225_LocationRequest::e_sourceInfo)
		? AsString(m_lrq.m_sourceInfo) : PString::Empty();
}

SetupAuthObj::SetupAuthObj(const SetupMsg & setup) : m_setup(setup)
{
}

PStringArray SetupAuthObj::GetPrefixes() const
{
	PStringArray array;
	if (m_setup.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_destinationAddress)) {
		const PINDEX ss = m_setup.GetUUIEBody().m_destinationAddress.GetSize();
		if (ss > 0) {
			array.SetSize(ss);
			for (PINDEX i = 0; i < ss; ++i)
				array[i] = AsString(m_setup.GetUUIEBody().m_destinationAddress[i], false);
		}
	}
	if (array.GetSize() == 0)
		array.AppendString(PString::Empty());
	return array;
}

PIPSocket::Address SetupAuthObj::GetIP() const
{
	PIPSocket::Address result;
	m_setup.GetPeerAddr(result);
	return result;
}

PString SetupAuthObj::GetAliases() const
{
	return m_setup.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress)
		? AsString(m_setup.GetUUIEBody().m_sourceAddress) : PString::Empty();
}

int AuthRule::Check(const AuthObj & aobj)
{
	if (Match(aobj) ^ m_inverted) {
		PTRACE(5, "GKAUTH\tPrefix auth rule '" << GetName() << "' matched");
		return m_fate;
	} else
		return m_next ? m_next->Check(aobj) : e_nomatch;
}

inline void delete_rule(PrefixAuth::Rules::value_type r)
{
	delete r.second;
	r.second = NULL;
}

IPAuthRule::IPAuthRule(Result fate, const PString & ipStr, bool inverted)
	: AuthRule(fate, inverted)
{
	Toolkit::GetNetworkFromString(ipStr, m_network, m_netmask);
	DWORD n = ~PIPSocket::Net2Host(DWORD(m_netmask));
	for (m_priority = 0; n; n >>= 1)
		++m_priority;
	SetName(PString((fate == e_allow) ? "allow ip(" : "deny ip(")
		+ PString(m_priority) + (inverted ? "):!" : "):") + ipStr);
}

bool IPAuthRule::Match(const AuthObj & aobj)
{
	return ((aobj.GetIP().GetVersion() == m_network.GetVersion()) && ((aobj.GetIP() & m_netmask) == m_network));
}

bool AliasAuthRule::Match(const AuthObj& aobj)
{
	return aobj.GetAliases().FindRegEx(m_pattern) != P_MAX_INDEX;
}

inline bool is_inverted(const PString & cfg, PINDEX p)
{
	return (p > 1) ? cfg[p-1] == '!' : false;
}

inline bool comp_authrule_priority(AuthRule *a1, AuthRule *a2)
{
	return *a1 < *a2;
}

namespace {
const char* const allowflag = "allow";
const char* const denyflag  = "deny"; // not used in code, because everything else defaults to DENY
const char* const ipflag    = "ip:";
const char* const ipv4flag  = "ipv4:";
const char* const ipv6flag  = "ipv6:";
const char* const aliasflag = "alias:";
}

// class PrefixAuth
PrefixAuth::PrefixAuth(
	const char * name,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks)
{
	m_defaultRule = GetDefaultStatus();

	const int ipfl = (int)strlen(ipflag);
	const int ipv4fl = (int)strlen(ipv4flag);
	const int ipv6fl = (int)strlen(ipv6flag);
	const int aliasfl = (int)strlen(aliasflag);

	const PStringToString cfgs = GetConfig()->GetAllKeyValues(name);
	for (PINDEX i = 0; i < cfgs.GetSize(); ++i) {
		PString key = cfgs.GetKeyAt(i);
		if (key *= "default") {
			m_defaultRule = Toolkit::AsBool(cfgs.GetDataAt(i)) ? e_ok : e_fail;
			continue;
		} else if (key *= "ALL") {
			// use space (0x20) as the key so it will be the last resort
			key = " ";
		}
		if (m_prefrules.find(key) != m_prefrules.end()) {
			PTRACE(1, "GKAUTH\t" << GetName() << " duplicate entry for "
				"destination '" << key << '\'');
			continue; //rule already exists? ignore
		}

		const PStringArray rules = cfgs.GetDataAt(i).Tokenise("|", false);
		const PINDEX sz = rules.GetSize();
		if (sz < 1) {
			PTRACE(1, "GKAUTH\t" << GetName() << " no rules found for "
				"destination '" << key << '\'');
			continue;
		}
		//AuthRule *rls[sz];
		AuthRule **rls = new AuthRule *[sz];
		for (PINDEX j = 0; j < sz; ++j) {
			// if not allowed, assume denial
			const AuthRule::Result fate = (rules[j].Find(allowflag) != P_MAX_INDEX)
				? AuthRule::e_allow : AuthRule::e_deny;
			PINDEX pp;
			if ((pp = rules[j].Find(ipflag)) != P_MAX_INDEX)
				rls[j] = new IPAuthRule(fate, rules[j].Mid(pp + ipfl).Trim(),
					is_inverted(rules[j], pp)
					);
			else if ((pp = rules[j].Find(ipv4flag)) != P_MAX_INDEX)
				rls[j] = new IPAuthRule(fate, rules[j].Mid(pp + ipv4fl).Trim(),
					is_inverted(rules[j], pp)
					);
			else if ((pp = rules[j].Find(ipv6flag)) != P_MAX_INDEX)
				rls[j] = new IPAuthRule(fate, rules[j].Mid(pp + ipv6fl).Trim(),
					is_inverted(rules[j], pp)
					);
			else if ((pp = rules[j].Find(aliasflag)) != P_MAX_INDEX)
				rls[j] = new AliasAuthRule(fate, rules[j].Mid(pp+aliasfl).Trim(),
					is_inverted(rules[j], pp)
					);
			else {
				rls[j] = new NullRule();
			}
		}

		// sort the rules by priority
		stable_sort(rls, rls + sz, comp_authrule_priority);
		for (PINDEX k = 1; k < sz; ++k)
			rls[k-1]->SetNext(rls[k]);
		m_prefrules[key] = rls[0];
		delete [] rls;
		rls = NULL;
	}

	if (m_prefrules.empty()) {
		PTRACE(1, "GKAUTH\t" << GetName() << " contains no rules - check the config");
	}
}

PrefixAuth::~PrefixAuth()
{
	for_each(m_prefrules.begin(), m_prefrules.end(), delete_rule);
}

int PrefixAuth::Check(RasPDU<H225_LocationRequest> & request, unsigned &)
{
	LRQAuthObj tmpObj((const H225_LocationRequest&)request); // fix for GCC 3.4.2
	return doCheck(tmpObj);
}

int PrefixAuth::Check(
	/// ARQ to be authenticated/authorized
	RasPDU<H225_AdmissionRequest> & request,
	/// authorization data (call duration limit, reject reason, ...)
	ARQAuthData & /*authData*/)
{
	H225_AdmissionRequest & arq = request;
	if (arq.m_answerCall
		&& arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier)
		&& CallTable::Instance()->FindCallRec(arq.m_callIdentifier)) {
		PTRACE(5, "GKAUTH\t" << GetName() << " ARQ check skipped - call "
			"already admitted and present in the call table");
		return e_ok;
	}
	ARQAuthObj tmpObj(arq); // fix for GCC 3.4.2
	return doCheck(tmpObj);
}

int PrefixAuth::Check(
	/// Q.931/H.225 Setup message to be authenticated
	SetupMsg & setup,
	/// authorization data (call duration limit, reject reason, ...)
	SetupAuthData & /*authData*/
	)
{
	SetupAuthObj tmpObj(setup); // fix for GCC 3.4.2
	return doCheck(tmpObj);
}

struct comp_pref { // function object
	comp_pref(const PString & s) : value(s) { }
	bool operator()(const PrefixAuth::Rules::value_type & v) const;
	const PString & value;
};

inline bool comp_pref::operator()(const PrefixAuth::Rules::value_type & v) const
{
	return (value.Find(v.first) == 0) || (v.first *= " ");
}

int PrefixAuth::doCheck(const AuthObj & aobj)
{
	if (!aobj.IsValid())
		return e_fail;

	const PStringArray destinationInfo(aobj.GetPrefixes());
	for (PINDEX i = 0; i < destinationInfo.GetSize(); ++i) {
		// find the first match rule
		// since prefrules is descendently sorted
		// it must be the most specific prefix
		for (Rules::iterator j = m_prefrules.begin(); j != m_prefrules.end(); ++j) {
			Rules::iterator iter = find_if(j, m_prefrules.end(), comp_pref(destinationInfo[i]));
			if (iter == m_prefrules.end())
				break;
			switch (iter->second->Check(aobj))
			{
			case AuthRule::e_allow:
				PTRACE(4, "GKAUTH\t" << GetName() << " rule matched and "
					"accepted destination prefix '"
					<< ((iter->first == " ") ? PString("ALL") : iter->first)
					<< "' for alias '" << destinationInfo[i] << '\'');
				return e_ok;

			case AuthRule::e_deny:
				PTRACE(4, "GKAUTH\t" << GetName() << " rule matched and "
					"rejected destination prefix '"
					<< ((iter->first == " ") ? PString("ALL") : iter->first)
					<< "' for alias '" << destinationInfo[i] << '\'');
				return e_fail;

			default: // try next prefix...
				j = iter;
				PTRACE(4, "GKAUTH\t" << GetName() << " rule matched and "
					"could not reject or accept destination prefix '"
					<< ((iter->first == " ") ? PString("ALL") : iter->first)
					<< "' for alias '" << destinationInfo[i] << '\'');
			}
		}
	}
	if (m_defaultRule == e_ok)
		PTRACE(4, "GKAUTH\t" << GetName() << " default rule accepted the request");
	else if (m_defaultRule == e_fail)
		PTRACE(4, "GKAUTH\t" << GetName() << " default rule rejected the request");
	else
		PTRACE(4, "GKAUTH\t" << GetName() << " could not reject or accept the request");
	return m_defaultRule;
}


#if defined(P_HTTP) || defined (HAS_LIBCURL)

class HttpPasswordAuth : public SimplePasswordAuth
{
public:
	/// build authenticator reading settings from the config
	HttpPasswordAuth(const char* authName);
	virtual ~HttpPasswordAuth();

protected:
	/** Override from SimplePasswordAuth.

	    @return
	    True if the password has been found for the given alias.
	*/
	virtual bool GetPassword(
		/// alias to check the password for
		const PString & alias,
		/// password string, if the match is found
		PString & password,
		/// map of authentication parameters
		std::map<PString, PString> & params
		);

private:
	HttpPasswordAuth();
	HttpPasswordAuth(const HttpPasswordAuth &);
	HttpPasswordAuth & operator=(const HttpPasswordAuth &);

protected:
	PString m_url;
	PString m_body;
	PCaselessString m_method;
	PRegularExpression m_resultRegex;
	PRegularExpression m_deleteRegex;
	PRegularExpression m_errorRegex;
};

HttpPasswordAuth::HttpPasswordAuth(const char* authName)
	: SimplePasswordAuth(authName)
{
	m_url = GkConfig()->GetString("HttpPasswordAuth", "URL", "");
	m_body = GkConfig()->GetString("HttpPasswordAuth", "Body", "");
	m_method = GkConfig()->GetString("HttpPasswordAuth", "Method", "POST");
	PString resultRegex = GkConfig()->GetString("HttpPasswordAuth", "ResultRegex", ".");
	m_resultRegex = PRegularExpression(resultRegex, PRegularExpression::Extended);
	m_resultRegex = PRegularExpression(resultRegex);
	if (m_resultRegex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Error '"<< m_resultRegex.GetErrorText() <<"' compiling ResultRegex: " << resultRegex);
		m_resultRegex = PRegularExpression(".", PRegularExpression::Extended);
	}
	PString deleteRegex = GkConfig()->GetString("HttpPasswordAuth", "DeleteRegex", "XXXXXXXXXX");   // default should never match
	m_deleteRegex = PRegularExpression(deleteRegex, PRegularExpression::Extended);
	if (m_deleteRegex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Error '"<< m_deleteRegex.GetErrorText() <<"' compiling DeleteRegex: " << deleteRegex);
		m_deleteRegex = PRegularExpression("XXXXXXXXXX", PRegularExpression::Extended);
	}
	PString errorRegex = GkConfig()->GetString("HttpPasswordAuth", "ErrorRegex", "^$");
	m_errorRegex = PRegularExpression(errorRegex, PRegularExpression::Extended);
	if (m_errorRegex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Error '"<< m_errorRegex.GetErrorText() <<"' compiling ErrorRegex: " << errorRegex);
		m_errorRegex = PRegularExpression("^$", PRegularExpression::Extended);
	}
}

HttpPasswordAuth::~HttpPasswordAuth()
{
}

#ifdef HAS_LIBCURL
// receives the document data
static size_t CurlWriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    *((PString*)userp) = PString((const char*)contents, size * nmemb);
    return size * nmemb;
}

// receives debug output
static int DebugToTrace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
  PTRACE (6, "CURL\t" << PString((const char *)data, size).Trim());
  return 0;
}
#endif // HAS_LIBCURL

bool HttpPasswordAuth::GetPassword(const PString & alias, PString & password, std::map<PString, PString> & params)
{
    PString result;

    PString url = ReplaceAuthParams(m_url, params);
    url = Toolkit::Instance()->ReplaceGlobalParams(url);
    url.Replace(" ", "%20", true);  // TODO: better URL escaping ?
    PTRACE(6, "HttpPasswordAuth\tURL=" << url);
    PString host = PURL(url).GetHostName();
    PString body = ReplaceAuthParams(m_body, params);
    body = Toolkit::Instance()->ReplaceGlobalParams(body);

#ifdef HAS_LIBCURL
    CURLcode curl_res = CURLE_FAILED_INIT;
    CURL * curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headerlist = NULL;
        if (m_method == "GET") {
            // nothing special to do
        } else if (m_method == "POST") {
            PStringArray parts = url.Tokenise("?");
            if (body.IsEmpty() && parts.GetSize() == 2) {
                url = parts[0];
                body = parts[1];
            } else {
                headerlist = curl_slist_append(headerlist, "Content-Type: text/plain");
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
            }
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)body);
        } else {
            PTRACE(2, "HttpPasswordAuth\tUnsupported method " << m_method);
        }
        curl_easy_setopt(curl, CURLOPT_URL, (const char *)url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
        if (PTrace::CanTrace(6)) {
            curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, DebugToTrace);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        }
        curl_res = curl_easy_perform(curl);
        curl_slist_free_all(headerlist);
        curl_easy_cleanup(curl);
    }

    if (curl_res != CURLE_OK) {
        PTRACE(2, "HttpPasswordAuth\tCould not GET password from " << host << " : " << curl_easy_strerror(curl_res));
        return false;
    }
#else
    PHTTPClient http;
    if (m_method == "GET") {
        if (!http.GetTextDocument(url, result)) {
            PTRACE(2, "HttpPasswordAuth\tCould not GET password from " << host);
            return false;
        }
    } else if (m_method == "POST") {
        PStringArray parts = url.Tokenise("?");
        if (body.IsEmpty() && parts.GetSize() == 2) {
            url = parts[0];
            body = parts[1];
        }
        PMIMEInfo outMIME;
        outMIME.SetAt(PMIMEInfo::ContentTypeTag(), "text/plain");
        PMIMEInfo replyMIME;
        if (!http.PostData(url, outMIME, body, replyMIME, result)) {
            PTRACE(2, "HttpPasswordAuth\tCould not POST to " << host);
            return false;
        }
    } else {
        PTRACE(2, "HttpPasswordAuth\tUnsupported method " << m_method);
        return false;
    }
#endif // HAS_LIBCURL

	PTRACE(5, "HttpPasswordAuth\tServer response = " << result);
    PINDEX pos, len;
    if (result.FindRegEx(m_errorRegex, pos, len)) {
        PTRACE(4, "HttpPasswordAuth\tErrorRegex matches result from " << host);
        return false;
    }
    if (result.FindRegEx(m_resultRegex, pos, len)) {
        password = result.Mid(pos, len);
        ReplaceRegEx(password, m_deleteRegex, "", true);
        PTRACE(5, "HttpPasswordAuth\tPassword = " << password);
        return true;
    } else {
        PTRACE(2, "HttpPasswordAuth\tError: No answer found in response from " << host);
        return false;
    }
}

#endif // P_HTTP

class TwoAliasAuth : public GkAuthenticator
{
public:
	enum SupportedRasChecks {
		TwoAliasAuthRasChecks = RasInfo<H225_RegistrationRequest>::flag,
		TwoAliasAuthMiscChecks = e_Setup | e_SetupUnreg
	};

	TwoAliasAuth(
		const char* name,
		unsigned supportedRasChecks = TwoAliasAuthRasChecks,
		unsigned supportedMiscChecks = TwoAliasAuthMiscChecks);

	virtual ~TwoAliasAuth() { }

	virtual int Check(RasPDU<H225_RegistrationRequest> & request, RRQAuthData & authData);

	virtual int Check(SetupMsg & setup, SetupAuthData & authData);

protected:
    virtual int doCheck(const H225_ArrayOf_AliasAddress & aliases);

private:
	TwoAliasAuth();
	TwoAliasAuth(const PrefixAuth &);
	TwoAliasAuth & operator=(const PrefixAuth &);
};

TwoAliasAuth::TwoAliasAuth(const char * name, unsigned supportedRasChecks, unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks)
{
}

int TwoAliasAuth::Check(RasPDU<H225_RegistrationRequest> & request, RRQAuthData & /*authData*/)
{
	H225_RegistrationRequest & rrq = request;

	if (!rrq.HasOptionalField(H225_RegistrationRequest::e_terminalAlias)) {
		PTRACE(3, "GKAUTH\t" << GetName() << " - terminalAlias field not found in RRQ message");
		return GetDefaultStatus();
	}

	const H225_ArrayOf_AliasAddress & aliases = rrq.m_terminalAlias;

    return doCheck(aliases);
}

int TwoAliasAuth::Check(SetupMsg & setup, SetupAuthData & /*authData*/)
{
	if (!setup.GetUUIEBody().HasOptionalField(H225_Setup_UUIE::e_sourceAddress)) {
		PTRACE(3, "GKAUTH\t" << GetName() << " - sourceAddress field not found in Setup message");
		return GetDefaultStatus();
	}

	const H225_ArrayOf_AliasAddress & aliases = setup.GetUUIEBody().m_sourceAddress;

    return doCheck(aliases);
}

int TwoAliasAuth::doCheck(const H225_ArrayOf_AliasAddress & aliases)
{
	for (PINDEX i = 0; i < aliases.GetSize(); i++) {
		const PString alias = AsString(aliases[i], false);
		const PString SecondAlias = GetConfig()->GetString("TwoAliasAuth", alias, "");
		if (!SecondAlias.IsEmpty()) {
            // check all aliases if we have it
            for (PINDEX j = 0; j < aliases.GetSize(); j++) {
                if (AsString(aliases[j], false) == SecondAlias) {
                    return e_ok;
                }
            }
		}
	}
	return GetDefaultStatus();
}


namespace { // anonymous namespace
	GkAuthCreator<GkAuthenticator> DefaultAuthenticatorCreator("default");
	GkAuthCreator<SimplePasswordAuth> SimplePasswordAuthCreator("SimplePasswordAuth");
#if H323_H350
	GkAuthCreator<H350PasswordAuth> SQLPasswordAuthCreator("H350PasswordAuth");
#endif
	GkAuthCreator<AliasAuth> AliasAuthCreator("AliasAuth");
	GkAuthCreator<PrefixAuth> PrefixAuthCreator("PrefixAuth");
#if defined(P_HTTP) || defined (HAS_LIBCURL)
	GkAuthCreator<HttpPasswordAuth> HttpPasswordAuthCreator("HttpPasswordAuth");
#endif
	GkAuthCreator<TwoAliasAuth> TwoAliasAuthCreator("TwoAliasAuth");
} // end of anonymous namespace
