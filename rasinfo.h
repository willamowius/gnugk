//////////////////////////////////////////////////////////////////
//
// rasinfo.h
//
// RAS type traits
// Define template classes that associate RAS tags and types
//
// Copyright (c) Citron Network Inc. 2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 05/28/2003
//
//////////////////////////////////////////////////////////////////

#ifndef RASINFO_H
#define RASINFO_H "@(#) $Id$"

// define a type for an RAS tag
template<int I> struct RasTag {
	operator unsigned() const { return I; }
};

// the template classes map RAS tags to its corresponding RAS types
template<int> struct RasType;

template<> struct RasType<H225_RasMessage::e_gatekeeperRequest> {
	typedef H225_GatekeeperRequest Type;
};
template<> struct RasType<H225_RasMessage::e_gatekeeperConfirm> {
	typedef H225_GatekeeperConfirm Type;
};
template<> struct RasType<H225_RasMessage::e_gatekeeperReject> {
	typedef H225_GatekeeperReject Type;
};
template<> struct RasType<H225_RasMessage::e_registrationRequest> {
	typedef H225_RegistrationRequest Type;
};
template<> struct RasType<H225_RasMessage::e_registrationConfirm> {
	typedef H225_RegistrationConfirm Type;
};
template<> struct RasType<H225_RasMessage::e_registrationReject> {
	typedef H225_RegistrationReject Type;
};
template<> struct RasType<H225_RasMessage::e_unregistrationRequest> {
	typedef H225_UnregistrationRequest Type;
};
template<> struct RasType<H225_RasMessage::e_unregistrationConfirm> {
	typedef H225_UnregistrationConfirm Type;
};
template<> struct RasType<H225_RasMessage::e_unregistrationReject> {
	typedef H225_UnregistrationReject Type;
};
template<> struct RasType<H225_RasMessage::e_admissionRequest> {
	typedef H225_AdmissionRequest Type;
};
template<> struct RasType<H225_RasMessage::e_admissionConfirm> {
	typedef H225_AdmissionConfirm Type;
};
template<> struct RasType<H225_RasMessage::e_admissionReject> {
	typedef H225_AdmissionReject Type;
};
template<> struct RasType<H225_RasMessage::e_bandwidthRequest> {
	typedef H225_BandwidthRequest Type;
};
template<> struct RasType<H225_RasMessage::e_bandwidthConfirm> {
	typedef H225_BandwidthConfirm Type;
};
template<> struct RasType<H225_RasMessage::e_bandwidthReject> {
	typedef H225_BandwidthReject Type;
};
template<> struct RasType<H225_RasMessage::e_disengageRequest> {
	typedef H225_DisengageRequest Type;
};
template<> struct RasType<H225_RasMessage::e_disengageConfirm> {
	typedef H225_DisengageConfirm Type;
};
template<> struct RasType<H225_RasMessage::e_disengageReject> {
	typedef H225_DisengageReject Type;
};
template<> struct RasType<H225_RasMessage::e_locationRequest> {
	typedef H225_LocationRequest Type;
};
template<> struct RasType<H225_RasMessage::e_locationConfirm> {
	typedef H225_LocationConfirm Type;
};
template<> struct RasType<H225_RasMessage::e_locationReject> {
	typedef H225_LocationReject Type;
};
template<> struct RasType<H225_RasMessage::e_infoRequest> {
	typedef H225_InfoRequest Type;
};
template<> struct RasType<H225_RasMessage::e_infoRequestResponse> {
	typedef H225_InfoRequestResponse Type;
};
template<> struct RasType<H225_RasMessage::e_nonStandardMessage> {
	typedef H225_NonStandardMessage Type;
};
template<> struct RasType<H225_RasMessage::e_unknownMessageResponse> {
	typedef H225_UnknownMessageResponse Type;
};
template<> struct RasType<H225_RasMessage::e_requestInProgress> {
	typedef H225_RequestInProgress Type;
};
template<> struct RasType<H225_RasMessage::e_resourcesAvailableIndicate> {
	typedef H225_ResourcesAvailableIndicate Type;
};
template<> struct RasType<H225_RasMessage::e_resourcesAvailableConfirm> {
	typedef H225_ResourcesAvailableConfirm Type;
};
template<> struct RasType<H225_RasMessage::e_infoRequestAck> {
	typedef H225_InfoRequestAck Type;
};
template<> struct RasType<H225_RasMessage::e_infoRequestNak> {
	typedef H225_InfoRequestNak Type;
};
template<> struct RasType<H225_RasMessage::e_serviceControlIndication> {
	typedef H225_ServiceControlIndication Type;
};
template<> struct RasType<H225_RasMessage::e_serviceControlResponse> {
	typedef H225_ServiceControlResponse Type;
};

// associate a tag and its type
template<int I> struct TagInfo {
	typedef RasTag<I> Tag;
	typedef typename RasType<I>::Type Type;
	enum {
		tag = I,
		// there are just 32 types of RAS, lucky!
		flag = (1 << I)
	};
};

// a dirty trick, but works :p
template<int I> struct RequestInfo : public TagInfo<I> {
	typedef RasTag<I+1> ConfirmTag;
	typedef RasTag<I+2> RejectTag;
	typedef typename RasType<I+1>::Type ConfirmType;
	typedef typename RasType<I+2>::Type RejectType;
};

template<int I> struct ConfirmInfo : public TagInfo<I> {
	typedef RasTag<I-1> RequestTag;
	typedef typename RasType<I-1>::Type RequestType;
};

template<int I> struct RejectInfo : public TagInfo<I> {
	typedef RasTag<I-2> RequestTag;
	typedef typename RasType<I-2>::Type RequestType;
};

// define an RAS request and all its associated types
template<class> struct RasInfo;

// RAS request
template<> struct RasInfo<H225_GatekeeperRequest> : public RequestInfo<H225_RasMessage::e_gatekeeperRequest> {};
template<> struct RasInfo<H225_RegistrationRequest> : public RequestInfo<H225_RasMessage::e_registrationRequest> {};
template<> struct RasInfo<H225_UnregistrationRequest> : public RequestInfo<H225_RasMessage::e_unregistrationRequest> {};
template<> struct RasInfo<H225_AdmissionRequest> : public RequestInfo<H225_RasMessage::e_admissionRequest> {};
template<> struct RasInfo<H225_BandwidthRequest> : public RequestInfo<H225_RasMessage::e_bandwidthRequest> {};
template<> struct RasInfo<H225_DisengageRequest> : public RequestInfo<H225_RasMessage::e_disengageRequest> {};
template<> struct RasInfo<H225_LocationRequest> : public RequestInfo<H225_RasMessage::e_locationRequest> {};

// RAS confirm
template<> struct RasInfo<H225_GatekeeperConfirm> : public ConfirmInfo<H225_RasMessage::e_gatekeeperConfirm> {};
template<> struct RasInfo<H225_RegistrationConfirm> : public ConfirmInfo<H225_RasMessage::e_registrationConfirm> {};
template<> struct RasInfo<H225_UnregistrationConfirm> : public ConfirmInfo<H225_RasMessage::e_unregistrationConfirm> {};
template<> struct RasInfo<H225_AdmissionConfirm> : public ConfirmInfo<H225_RasMessage::e_admissionConfirm> {};
template<> struct RasInfo<H225_BandwidthConfirm> : public ConfirmInfo<H225_RasMessage::e_bandwidthConfirm> {};
template<> struct RasInfo<H225_DisengageConfirm> : public ConfirmInfo<H225_RasMessage::e_disengageConfirm> {};
template<> struct RasInfo<H225_LocationConfirm> : public ConfirmInfo<H225_RasMessage::e_locationConfirm> {};

// RAS reject
template<> struct RasInfo<H225_GatekeeperReject> : public RejectInfo<H225_RasMessage::e_gatekeeperReject> {};
template<> struct RasInfo<H225_RegistrationReject> : public RejectInfo<H225_RasMessage::e_registrationReject> {};
template<> struct RasInfo<H225_UnregistrationReject> : public RejectInfo<H225_RasMessage::e_unregistrationReject> {};
template<> struct RasInfo<H225_AdmissionReject> : public RejectInfo<H225_RasMessage::e_admissionReject> {};
template<> struct RasInfo<H225_BandwidthReject> : public RejectInfo<H225_RasMessage::e_bandwidthReject> {};
template<> struct RasInfo<H225_DisengageReject> : public RejectInfo<H225_RasMessage::e_disengageReject> {};
template<> struct RasInfo<H225_LocationReject> : public RejectInfo<H225_RasMessage::e_locationReject> {};

// others
template<> struct RasInfo<H225_InfoRequest> : public TagInfo<H225_RasMessage::e_infoRequest> {};
template<> struct RasInfo<H225_InfoRequestResponse> : public TagInfo<H225_RasMessage::e_infoRequestResponse> {
	typedef RasTag<tag+6> ConfirmTag;
	typedef RasTag<tag+7> RejectTag;
	typedef RasType<tag+6>::Type ConfirmType;
	typedef RasType<tag+7>::Type RejectType;
};
template<> struct RasInfo<H225_NonStandardMessage> : public TagInfo<H225_RasMessage::e_nonStandardMessage> {};
template<> struct RasInfo<H225_UnknownMessageResponse> : public TagInfo<H225_RasMessage::e_unknownMessageResponse> {};
template<> struct RasInfo<H225_RequestInProgress> : public TagInfo<H225_RasMessage::e_requestInProgress> {};
template<> struct RasInfo<H225_ResourcesAvailableIndicate> : public TagInfo<H225_RasMessage::e_resourcesAvailableIndicate> {
	typedef RasTag<tag+1> ConfirmTag;
	typedef RasType<tag+1>::Type ConfirmType;
};
template<> struct RasInfo<H225_ResourcesAvailableConfirm> : public TagInfo<H225_RasMessage::e_resourcesAvailableConfirm> {};
template<> struct RasInfo<H225_InfoRequestAck> : public TagInfo<H225_RasMessage::e_infoRequestAck> {};
template<> struct RasInfo<H225_InfoRequestNak> : public TagInfo<H225_RasMessage::e_infoRequestNak> {};
template<> struct RasInfo<H225_ServiceControlIndication> : public TagInfo<H225_RasMessage::e_serviceControlIndication> {};
template<> struct RasInfo<H225_ServiceControlResponse> : public TagInfo<H225_RasMessage::e_serviceControlResponse> {};

#endif // RASINFO_H
