/* AVAYA specific data */

#ifndef AVAYA_H
#define AVAYA_H

/* For AVAYA inter-packet delay */
#define		SETUP_SLEEP	PThread::Sleep(1)

static const char OID_AVAYA_Auth_pwdSymEnc[] = "1.3.14.3.2.6"; // DES ECB
static const char OID_AVAYA_Auth_keyExch[] = "2.16.840.1.114187.1.3"; // DES CTS
static const char OID_AVAYA_Feature9[] = "2.16.840.1.114187.1.9";
static const char OID_AVAYA_Feature10[] = "2.16.840.1.114187.1.10";

static const char OID_AVAYA_H221nonStandardId[] = "2.16.840.1.113778.4.2.1";

static const unsigned char CCMS_discovertRequest_Id = 0x85;
static const unsigned char CCMS_loginRequest_Id = 0x81;
static const unsigned char CCMS_loginAccepted_Id = 0x2c;
static const unsigned char CCMS_switchInfoRequest_Id = 0x40;		/* 4010 = switchInfoRequest? */
static const unsigned char CCMS_switchInfoResponse_Id = 0x50; 		/* 5060 - requestResult = requestComplete */
static const unsigned char CCMS_switchInfoResponseMoreData_Id = 0x51;	/* 5160 - requestResult = moreData */
static const unsigned char CCMS_switchHookResponseOnhook[] = {0x05, 0x38, 0x00, 0x80, 0x01};	/* 5 = totalLen, 81A0501, 0x80 0x01 - onhook */
static const unsigned char CCMS_switchHookResponseOnhook2[] = {0x05, 0x38, 0x00, 0x81, 0x01};	/* 5 = totalLen, 81A0501, 0x81 0x01 - onhook */
static const unsigned char CCMS_switchHookResponseOffhook[] = {0x05, 0x38, 0x00, 0x80, 0x02};	/* 5 = totalLen, 81A0501, 0x80 0x02 - offhook? (Handset) */
static const unsigned char CCMS_switchHookResponseOffhook2[] = {0x05, 0x38, 0x00, 0x60, 0x07};	/* 5 = totalLen  81A0501, 0x60 0x07 - offhook? (CA1 select) */
static const unsigned char CCMS_switchHookResponseOffHook3[] = {0x05, 0x38, 0x00, 0x81, 0x02};  /* 5 = totalLen, 81A0501, 0x81 0x02 - offhook? (Speaker on) */
static const unsigned char CCMS_terminalIDResponse[] = {0x0a, 0x38, 0x47, 0x00, 0xc0, 0x0b, 0x36, 0x60, 0x08, 0x40}; /* 10 = totalLen */
static const unsigned char CCMS_discoveryRequest[] = {0x85, 0x01, 0x40}; /* natTerminal=NULL */
static const unsigned char CCMS_dialpadButtonX[] = {0x05, 0x38, 0x00, 0x7f}; /* totalLen is 5, but mask is 4 bytes only, at [4] actual button pressed */
static const unsigned char CCMS_dialpadButton0[] = {0x05, 0x38, 0x00, 0x7f, 0x0a};
static const unsigned char CCMS_dialpadButton1[] = {0x05, 0x38, 0x00, 0x7f, 0x01};
static const unsigned char CCMS_dialpadButton2[] = {0x05, 0x38, 0x00, 0x7f, 0x02};
static const unsigned char CCMS_dialpadButton3[] = {0x05, 0x38, 0x00, 0x7f, 0x03};
static const unsigned char CCMS_dialpadButton4[] = {0x05, 0x38, 0x00, 0x7f, 0x04};
static const unsigned char CCMS_dialpadButton5[] = {0x05, 0x38, 0x00, 0x7f, 0x05};
static const unsigned char CCMS_dialpadButton6[] = {0x05, 0x38, 0x00, 0x7f, 0x06};
static const unsigned char CCMS_dialpadButton7[] = {0x05, 0x38, 0x00, 0x7f, 0x07};
static const unsigned char CCMS_dialpadButton8[] = {0x05, 0x38, 0x00, 0x7f, 0x08};
static const unsigned char CCMS_dialpadButton9[] = {0x05, 0x38, 0x00, 0x7f, 0x09};



#include "avaya_station_1000.h"

#endif


