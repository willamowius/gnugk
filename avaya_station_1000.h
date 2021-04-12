#ifndef AVAYA_STATION_1000_H
#define AVAYA_STATION_1000_H

static const unsigned char CCMS_loginRequest_1000[] = {
	0x09, 0x81,	/* Len, Cmd ? */
	0x01, 0x00,	/* forceLogin */
	0x26, 0x1e, 0x9e, 0x00, 0x01, 0x20,		/* ? */

	0x01, 0x00,	/* emergencyCallHandling */
	0x06, 0xb4, 0xb0, 0x17, 0x8d, 0x29, 0xc6,	/* macAddress */
	0x01, 0x00,
	0x05, 0xc0, 0x02, 0x00, 0x00, 0x2f,		/* unicodeScript */
	0x01, 0x00,	/* ttiCapable */
	0x01, 0x80,	/* sendButtonInfo */
	0x01, 0x00,	/* sendSwitchRelease */
	0x01, 0x00	/* sendStationInfo */
/*
	forceLogin FALSE,
	audioCapable TRUE,
	callSigProtocol h323AnnexL-P : NULL,
	connectionType lan : NULL,
	emergencyCallHandling emerExtension : NULL,
	macAddress 'B4B0178D29C6'H,
	signalingChannelRecoveryAlgorithmVersion 1,
	unicodeScript 33554479,
	ttiCapable NULL,
	sendButtonInfo TRUE,
	sendSwitchRelease NULL,
	sendStationInfo NULL
*/
};

static const unsigned char CCMS_loginAccepted_1000[] = {
	0x2c,	/* Cmd/Len? */
	0x40, 0x4d, 0x61, 0x69, 0x6e,	/* Len=4, Location name "Main" */
	0x2b, 0xb3, 0x7c, 0x00, 0x01, 0x40, 0x27, 0x03, 0xf4,
	/* QoS audio params */
	0x60, 0x00,	/* L2param 24576 [15]*/
	0x00, 0x2e,	/* L3param 46 [17] */
	0x00,		/* L4param NULL */
	0x08, 0x00,	/* L4 low port 2048 [20] */
	0x0d, 0x01,	/* L4 high port 3329 [22] */
	0x03, 0x80, 0x09, 0x78,		/* rtcpControl TRUE? */
	0x00, 0x00, 0x00, 0x00,		/* rtcpMonitor IP 0.0.0.0 [28] */
	0x13, 0x8d,			/* rtcpMonitor port 5005 [32] */
	0x00, 0x04, 0x04, 0x78, 0x00, 0x0e, 0x80, 0x60,	/* rsvpRefreshInterval 15 [39] */
	/* QoS service params */
	0x60, 0x00,	/* L2param 24576 [42] */
	0x00, 0x2e,	/* L3param 46 [44] */
	0x28, 0x00, 0x01, 0x00,
	0x00, 0x2e,	/* Service BBE NULL, L3 46 [50] */
	0x01, 0x00, 0x0a, 0x62, 0x00, 0x13, 0x04, 0x00, 0x04,	/* tcpKeepaliveTime=20 [57], NumberOfTransmits=5 [58], KeepaliveInterval=5 [60] */
	0x00, 0x4b,	/* Primary search time 75 [61] */
	0x04, 0xb0,	/* Primary registration timer 1200 [63] */
	0x01, 0x00,	/* uriDialing NULL */
	0x01, 0x00,	/* blockDialing NULL */
	0x20, 0x04,	/* buttonInfo: 4 buttons [70] */
	/* Button ****************************************************** [71] */
	0xc0,
	0x70,		/* Index 7 */
	0x00, 0x06,	/* Type 6 */
	0x20,				/* Len >> 3 */
	0x31, 0x30, 0x30, 0x30,		/* auxInfo "1000" [76] */
	0x09, 0x80, 0x05,
	0x04,				/* ButtonLabel Len */
	0x31, 0x30, 0x30, 0x30,		/* ButtonLabel "1000" [84] */
	0x01, 0xa8,	/* Flags 168 */
	/* Expansion *************************************************** [90] */
	0x0c,
	0x10,		/* Index 1 */
	0x00, 0x42,	/* Type 66 */
	/* Expansion *************************************************** [94] */
	0x0c,
	0x20,		/* Index 2 */
	0x00, 0x0f,	/* Type 15 */
	/* Expansion *************************************************** [98] */
	0x0c, 
	0x30,		/* Index 3 */
	0x01, 0x46,	/* Type 326 */
	0x01, 0x50,	/* Flags 80 */
	0x03, 0x00,	/* genericOptions options 0 */
	0x00, 0xef,	/* genericOptions mask 239 */
	0x11,	/* Len = 17? */
	0x80,
	/* "R018x.01.0.890.0" */
	0x52, 0x30, 0x31, 0x38, 0x78, 0x2e, 0x30, 0x31, 0x2e, 0x30, 0x2e, 0x38, 0x39, 0x30, 0x2e, 0x30,
	0x03,	/* stationInfo Len = 3? */
	0x00,
	0xee,	/* stationInfo setType = 238 (AVAYA 1608) [128] */
	0x60	/* stationInfo b5=dispModEquip=TRUE b6=covgModEquip=TRUE [129] */
};

static const unsigned char CCMS_loginAccepted_1000_NEW[] = {
	0x2c,
	0x40, 0x4d, 0x61, 0x69,	0x6e,	/* Len=4, Location name "Main" */
	0x2b, 0xb3, 0x7c, 0x00, 0x01, 0x40, 0x27, 0x03, 0xf4,
	/* QoS audio params */
	0x60, 0x00,						/* L2param 24576 [] */
	0x00, 0x2e,						/* L3param 46 [] */
	0x00, 
	0x08, 0x00,						/* L4 low port 2048 [] */
	0x0d, 0x01,						/* L4 high port 3329 [] */
	/* RTCP */
	0x03, 0x80, 0x09, 0x78,			/* rtcpControl TRUE */
	0x00, 0x00, 0x00, 0x00,			/* rtcpMonitor IP 0.0.0.0 [] */
	0x13, 0x8d,						/* rtcpMonitor port 5005 [] */
	0x00, 0x04, 					/* rtcpFlowRate 5 [] */
	/* RSVP */
	0x04, 0x78, 					/* rsvpControl FALSE */
	0x00, 0x0e, 					/* rsvpRefreshInterval 15 */
	0x80, 0x60,						/* rsvpFailedRetryReservation TRUE, rsvpProfile guaranteed */
	/* QoS service params */
	0x60, 0x00,						/* L2param 24576 [] */
	0x00, 0x2e,						/* L3param 46 [] */
	0x28, 0x00, 0x01, 0x00, 
	0x00, 0x2e, 					/* Service BBE NULL L3param 46 [] */
	0x01, 0x00, 					/* signalingChannelRecoveryAlgo version 1 */
	0x0a, 0x62, 0x00, 0x13, 0x04, 0x00, 0x04, /* tcpKeepaliveTime=20, NumberOfTransmits=5, KeepaliveInterval=5 */
	0x00, 0x4b,						/* Primary search time 75 [] */
	0x04, 0xb0,						/* Primary registration timer 1200 [] */
	0x01, 0x00,						/* uriDialing NULL */
	0x01, 0x00,						/* blockDialing NULL [] */
	
	/* buttonInfo 6 buttons */
	0x46, 0x06,

	0xc0,							/* buttonModule prinModule */
	0x70,							/* buttonIndex 7 */
	0x00, 0x06,						/* buttonType 6 */
	0x20,
	0x31, 0x30, 0x30, 0x30,			/* auxInfo "1000" */
	0x09, 0x80, 0x05,
	0x04,							/* buttonLabel len */
	0x31, 0x30, 0x30, 0x30, 		/* buttonLabel2 "1000" */
	0x01, 0xa8,						/* buttonFlags 168 */
	
	0xc0,							/* buttonModule prinModule */
	0x80,							/* buttonIndex 8 */
	0x00, 0x06,						/* buttonType 6 */
	0x20,
	0x31, 0x30, 0x30, 0x30,			/* auxInfo "1000" */
	0x09, 0x80, 0x05,
	0x04,							/* buttonLabel len */
	0x31, 0x30, 0x30, 0x30,			/* buttonLabel2 "1000" */
	0x01, 0xa8,						/* buttonFlags 168 */
	
	0xc0, 							/* buttonModule prinModule */
	0x90,							/* buttonIndex 9 */
	0x00, 0x06,						/* buttonType 6 */
	0x20,
	0x31, 0x30, 0x30, 0x30,			/* auxInfo "1000" */
	0x09, 0x80, 0x05,
	0x04,							/* buttonLabel len */
	0x31, 0x30, 0x30, 0x30,			/* buttonLabel2 "1000" */
	0x01, 0xa8,						/* buttonFlags 168 */
	
	0x0c,							/* buttonModule covgExpansionModule */ 
	0x10,							/* buttonIndex 1 */
	0x00, 0x42,						/* buttonType 66 */

	0x0c,							/* buttonModule covgExpansionModule */ 
	0x20,							/* buttonIndex 2 */
	0x00, 0x0f,						/* buttonType 15 */

	0x0c,							/* buttonModule covgExpansionModule */ 
	0x30,							/* buttonIndex 3 */
	0x01, 0x46,						/* buttonType 326 */

	0x01, 0x50,						/* primaryFlags 80 */

	0x03, 0x00,						/* genericOptions 0 */
	0x00, 0xef,						/* mask 239 */

	0x11,							/* switchRelease len 17 */
	0x80,
	0x52, 0x30, 0x31, 0x38, 0x78, 0x2e, 0x30, 0x31, 0x2e, 0x30, 0x2e, 0x38, 0x39, 0x30, 0x2e, 0x30, /* "R018x.01.0.890.0" */
	0x03,
	0x00,
	0xee,							/* stationInfo setType 238 */
	0x60							/* stationInfo featModEquip FALSE dispModeEquip covgModEquip TRUE */
};

static const unsigned char CCMS_switchInfoResponse_1000_Complete[] = {
	0x50, 0x60, 
	0x04,	/* buttonInfo: 4 buttons */
	/* Button ******************************************************/
	0x40,
	0x70,		/* Index 7 */
	0x00, 0x06,	/* Type 6 */
	0x20,				/* Len >> 3 */
	0x31, 0x30, 0x30, 0x30,		/* auxInfo "1000" [8] */
	/* Expansion ***************************************************/
	0x0c,
	0x10,		/* Index 1 */
	0x00, 0x42,	/* Type 66 */
	/* Expansion ***************************************************/
	0x0c,
	0x20,		/* Index 2 */
	0x00, 0x0f,	/* Type 15 */
	/* Expansion ***************************************************/
	0x0c,
	0x30,		/* Index 3 */
	0x01, 0x46	/* Type 326 */
};

static const unsigned char CCMS_switchInfoResponse_1000_Complete_NEW[] = {
	0x50,					/* switchInfoResponse */
	0x60,					/* requestResult = requestComplete */
	0x06,					/* responseData = buttonInfo for 6 buttons */

	0x40,					/* buttonModule = prinModule*/
	0x70,					/* buttonIndex 7 */
	0x00, 0x06,				/* buttonType 6 */
	0x20,
	0x31, 0x30, 0x30, 0x30,	/* auxInfo "1000" */

	0x40,					/* buttonModule = prinModule */
	0x80,					/* buttonIndex 8 */
	0x00, 0x06,				/* buttonType 6 */
	0x20,
	0x31, 0x30, 0x30, 0x30,	/* auxInfo "1000" */
	
	0x40,					/* buttonModule = prinModule */
	0x90,					/* buttonIndex 9 */
	0x00, 0x06,				/* buttonType 6 */
	0x20,
	0x31, 0x30, 0x30, 0x30,	/* auxInfo "1000" */
	
	0x0c,					/* buttonModule = covgExpansionModule */
	0x10,					/* buttonIndex 1 */
	0x00, 0x42,				/* buttonType 66 */
	
	0x0c,					/* buttonModule = covgExpansionModule */
	0x20,					/* buttonIndex 2 */
	0x00, 0x0f,				/* buttonType 15 */
	
	0x0c,					/* buttonModule = covgExpansionModule */
	0x30,					/* buttonIndex 3 */
	0x01, 0x46				/* buttonType 326 */
};
/* CCMS Structure:
	[0]		- msg length
	[1-3]		- msg address (from)
	[4 b7]		- msg downlink
	[4 b5]		- msg [4 b0-4] contains variable opcode len
*/

/* AUX CTRL:
	- Activate Terminal
	- SwitchHook state Inquiry
*/
static const unsigned char CCMS_vdtUpdate_auxActivateTerminal[] = { /*10*/
	0x06,			/* Len */
	0x38, 0x11, 0x20, 	/* 81A0501 */
	0x82,		/* auxActivateTerminal */
	0x88		/* switchHookInquiry */
};

/* LOAD DISPLAY:
*/
static const unsigned char CCMS_vdtUpdate_loadDisplay[] = { /*12*/
	0x1c,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xab, 0xe3, 		/* loadDisplay (E3?) */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[;Hesc[stxK */
	0x1b, 0x5b, 0x02, 0x4b,
	0xab, 0xe3, 		/* loadDisplay (E3?) */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[;esc[stxK */
	0x1b, 0x5b, 0x02, 0x4b
};

/* DISPLAY MODULE:
	- Control mode Inspect
*/
static const unsigned char CCMS_vdtUpdate_displayModuleInspect[] = { /*14*/
	0x08,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa3, 0x83, 0x04, 0x42
};

/* TERMINAL:
	- Personal ring change, code=0
*/
static const unsigned char CCMS_vdtUpdate_terminalRingChange[] = { /*16*/
	0x08,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa3, 0x80, 0x09, 0x00	/* personalRingChange code=0 */
};

/* TERMINAL:
	- Display control (0xE0?), update time & date
*/
static const unsigned char CCMS_vdtUpdate_displayUpdateDateTime[] = { /*18&22&28&36*/
	0x0e,			/* Len 14 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa9, 0xe0,		/* update date&time */
	0x07, 0x00,		/* show am/pm: show date w/ month 1st (mm/dd/yy) */
	0x0a,			/* Hour=10 [8]*/
	0x12,			/* Minute=18 [9] */
	0x16,			/* Second=22 [10] */
	0x0d,			/* Day of Month=13 [11] */
	0x06,			/* Month of the Year=6 [12] */
	0x14			/* Year modulus 100=20 [13] */
};
static const int CCMS_vdtUpdate_displayUpdateDateTime_Length = sizeof(CCMS_vdtUpdate_displayUpdateDateTime);

/* TERMINAL:
	- TT admin, no info on S
*/
static const unsigned char CCMS_vdtUpdate_terminalTTNoInfo[] = {/*20*/
	0x07,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa2, 0x80, 0x05	/* TT admin no info on S */
};

/* LOAD DISPLAY (E3?) + LAMP UPDATE */
/* Lamp numbering value: 
	0x80 - terminal, 0x82 - coverage module
	0x20 - dark, 0x2f - steady

	(Red even, green odd)
	B#  R G
	0T0 0 1
	0T1 2 3
	0T2 4 5
	0T3 6 7
	0T4 8 9
	0T5 a b
	0T6 c d
	0T7 e f
	0T8 10 11
*/
static const unsigned char CCMS_vdtUpdate_loadDisplayLamp1[] = {/*24*/
	0x1d,			/* Len 28 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xab, 0xe3,		/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[;esc[stxK */
	0x1b, 0x5b, 0x02, 0x4b,
	0xac,			/* lampUpdate */
	0x80, 0x2f, 0x0e,	/* terminal lamp steady 0T7 red */
	0x82, 0x2f, 0x05,	/* coverage lamp steady 0T2 green */
	0x80, 0x20, 0x10,	/* terminal lamp dark 0T8 red */
	0x80, 0x2f, 0x0e	/* terminal lamp steady 0T7 red */
};

/* LAMP UPDATE */
static const unsigned char CCMS_vdtUpdate_loadDisplayLamp2[] = {/*26*/
	0x08,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa3,			/* lampUpdate? */
	0x82, 0x2f, 0x05	/* coverage lamp steady 0T2 green */
};

/* LAMP UPDATE */
static const unsigned char CCMS_vdtUpdate_loadDisplayLamp3[] = {/*30*/
	0x0e,			/* Len 14 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa9,			/* lampUpdate? */
	0x80, 0x20, 0x0d,	/* terminal lamp dark 0T6 green */
	0x80, 0x20, 0x0f,	/* terminal lamp dark 0T7 green */
	0x80, 0x2f, 0x0e	/* terminal lamp steady 0T7 red */
};

/* LAMP UPDATE */
static const unsigned char CCMS_vdtUpdate_loadDisplayLamp4[] = {/*34*/
	0x08,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa3,			/* lampUpdate? */
	0x82, 0x2f, 0x05	/* coverage lamp steady 0T2 greep */
};

/* LAMP UPDATE */
static const unsigned char CCMS_vdtUpdate_loadDisplayLamp5[] = {/*38*/
	0x0e,			/* Len 14 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa9,			/* lampUpdate? */
	0x80, 0x20, 0x0d,	/* terminal lamp dark 0T6 green */
	0x80, 0x20, 0x0f,	/* terminal lamp dark 0T7 green */
	0x80, 0x2f, 0x0e,	/* terminal lamp steady 0T7 red */
};

/* LAMP UPDATE */
static const unsigned char CCMS_vdtUpdate_loadDisplayLamp6[] = {/*40*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x11,	/* terminal lamp dark 0T8 green */
	0x80, 0x20, 0x10,	/* terminal lamp dark 0T8 red */
	0x80, 0x20, 0x13,	/* terminal lamp dark 0T9 green */
	0x80, 0x20, 0x12,	/* terminal lamp dark 0T9 red */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp7[] = {/*42*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x15,	/* terminal lamp dark 0T10 green */
	0x80, 0x20, 0x14,	/* terminal lamp dark 0T10 red */
	0x80, 0x20, 0x17,	/* terminal lamp dark 0T11 green */
	0x80, 0x20, 0x16,	/* terminal lamp dark 0T11 red */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp8[] = {/*44*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x19,	/* terminal lamp dark 0T12 green */
	0x80, 0x20, 0x18,	/* terminal lamp dark 0T12 red */
	0x80, 0x20, 0x1b,	/* terminal lamp dark 0T13 green */
	0x80, 0x20, 0x1a,	/* terminal lamp dark 0T13 red */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp9[] = {/*46*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x1d,	/* terminal lamp dark 0T14 green */
	0x80, 0x20, 0x1c,	/* terminal lamp dark 0T14 red */
	0x80, 0x20, 0x1f,	/* terminal lamp dark 0T15 green */
	0x80, 0x20, 0x21,	/* terminal lamp dark 0T16 green */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp10[] = {/*48*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x23,	/* terminal lamp dark 0T17 green */
	0x80, 0x20, 0x25,	/* terminal lamp dark 0T18 green */
	0x80, 0x20, 0x27,	/* terminal lamp dark 0T19 green */
	0x80, 0x20, 0x29,	/* terminal lamp dark 0T20 green */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp11[] = {/*50*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x2b,	/* terminal lamp dark 0T21 green */
	0x80, 0x20, 0x2d,	/* terminal lamp dark 0T22 green */
	0x80, 0x20, 0x2f,	/* terminal lamp dark 0T23 green */
	0x80, 0x20, 0x31,	/* terminal lamp dark 0T24 green */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp12[] = {/*52*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x33,	/* terminal lamp dark 0T25 green */
	0x80, 0x20, 0x35,	/* terminal lamp dark 0T26 green */
	0x80, 0x20, 0x37,	/* terminal lamp dark 0T27 green */
	0x80, 0x20, 0x39,	/* terminal lamp dark 0T28 green */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp13[] = {/*54*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x3b,	/* terminal lamp dark 0T29 green */
	0x80, 0x20, 0x3d,	/* terminal lamp dark 0T30 green */
	0x80, 0x20, 0x3f,	/* terminal lamp dark 0T31 green */
	0x80, 0x20, 0x41,	/* terminal lamp dark 0T32 green */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp14[] = {/*56*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x43,	/* terminal lamp dark 0T33 green */
	0x80, 0x20, 0x45,	/* terminal lamp dark 0T34 green */
	0x80, 0x20, 0x47,	/* terminal lamp dark 0T35 green */
	0x80, 0x20, 0x49,	/* terminal lamp dark 0T36 green */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp15[] = {/*58*/
	0x11,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac,			/* lampUpdate? */
	0x80, 0x20, 0x4b,	/* terminal lamp dark 0T37 green */
	0x80, 0x20, 0x4d,	/* terminal lamp dark 0T38 green */
	0x80, 0x20, 0x4f,	/* terminal lamp dark 0T39 green */
	0x80, 0x20, 0x51,	/* terminal lamp dark 0T40 green */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayLamp16[] = {/*60*/
	0x0e,			/* Len 17 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa9,			/* lampUpdate? */
	0x82, 0x20, 0x03,	/* coverage lamp dark 0T1 green */
	0x82, 0x2f, 0x05,	/* coverage lamp steady 0T2 green */
	0x82, 0x20, 0x07,	/* coverage lamp dark 0T3 green */
}; 

static const unsigned char CCMS_vdtUpdate_switchHookInquiry[] = {/*62*/
	0x05,
	0x38, 0x11, 0x20,
	0x88			/* switchHookInquiry */
};

static const unsigned char CCMS_vdtUpdate_terminalIDReq[] = { /*32? &66*/
	0x07,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa2, 0xa0, 0x0b	/* nonDestructive ID Req */
};

/* Maximum name length = 14+13 = 27 chars */
static const unsigned char CCMS_vdtUpdate_ringerDisplayName[] = {
	0x14,			/* Len 20 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0x4b,			/* ringerChange = standard Ring */
	0xae, 0xe3,		/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[; */
	0x1b, 0x5b, 0x02, 0x4b, 0x01, 0x3d, 0x54	/* esc[stxKsoh=T[19] */
};
static const int CCMS_vdtUpdate_ringerDisplayName_Length = sizeof(CCMS_vdtUpdate_ringerDisplayName);

static const unsigned char CCMS_vdtUpdate_ringerDisplayName_NEW[] = {
	0x14,			/* Len 20 */
	0x38, 0x11, 0x20,	/* 81A0501 */
    0x4b,			/* ringerChange = standard ring (0x4b), DID/attendant ring (0x4c) */
	0xae, 0xe3,		/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[; */
	0x1b, 0x5b, 0x02, 0x4b, 0x01, 0x3d, 0x4b	/* esc[stxKsoh=K[19] */
};
static const int CCMS_vdtUpdate_ringerDisplayName_NEW_Length = sizeof(CCMS_vdtUpdate_ringerDisplayName_NEW);

static const unsigned char CCMS_vdtUpdate_loadDisplayName[] = {
	0x13,			/* Len 19 */
	0x38, 0x11, 0x20,
	0xae, 0xe3,		/* loadDisplay */
	0x65, 0x73, 0x74, 0x20, 0x32, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 /* est_2_..._ total len=13[6] */
};
static const int CCMS_vdtUpdate_loadDisplayName_Length = sizeof(CCMS_vdtUpdate_loadDisplayName);

static const unsigned char CCMS_vdtUpdate_loadDisplayName_NEW[] = {
	0x13,			/* Len 19 */
	0x38, 0x11, 0x20,
	0xae, 0xe3,		/* loadDisplay */
	0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x69, 0x6e, 0x20, 0x50, 0x72, 0x6f /* onstantin Pro total len=13[6] */
};
static const int CCMS_vdtUpdate_loadDisplayName_NEW_Length = sizeof(CCMS_vdtUpdate_loadDisplayName_NEW);

static const unsigned char CCMS_vdtUpdate_loadDisplayName2[] = {
	0x13,			/* Len 19 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xae, 0xe3,		/* loadDisplay */
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 /* __...__ total len=13[6] */
};
static const int CCMS_vdtUpdate_loadDisplayName2_Length = sizeof(CCMS_vdtUpdate_loadDisplayName2);

static const unsigned char CCMS_vdtUpdate_loadDisplayNum[] = {
	0x17,			/* Len 23 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xae, 0xe3,		/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x1d, 0x48, 0x20, 0x31, 0x30, 0x30, 0x31, 0x20, 0x20, /* esc[;gsH_1001__ total len=7[12->13] */
	0xa3, 0xe3, 0x20, 0x20	/* loadDisplay = __ */
};
static const int CCMS_vdtUpdate_loadDisplayNum_Length = sizeof(CCMS_vdtUpdate_loadDisplayNum);

static const unsigned char CCMS_vdtUpdate_loadDisplayNum_NEW[] = {
	0x13,			/* Len 19 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xae, 0xe3,		/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x11, 0x48, 0x20, 0x20, 0x20, 0x33, 0x38, 0x30, 0x35	/*esc[;dc1H___3805 total len=7[12->13] */
};
static const int CCMS_vdtUpdate_loadDisplayNum_NEW_Length = sizeof(CCMS_vdtUpdate_loadDisplayNum_NEW);

static const unsigned char CCMS_vdtUpdate_loadDisplayNum2_NEW[] = {
	0x19,			/* Len 25 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac, 0xe3, 0x30, 0x33, 0x35, 0x35, 0x34, 0x32, 0x32, 0x33, 0x30, 0x31, 0x32,	/* loadDisplay? 03554223012 total len=11[6] */
	0xa7, 0xe3,		/* loadDisplay */
	0x1b, 0x54, 0x02, 0x0e, 0x14, 0x0f	/* escTstxsodc4si */
};
static const int CCMS_vdtUpdate_loadDisplayNum2_NEW_Length = sizeof(CCMS_vdtUpdate_loadDisplayNum2_NEW);

static const unsigned char CCMS_vdtUpdate_loadDisplayCA1Flash[] = {
	0x10,			/* Len 16 */
	0x38, 0x11, 0x20,
	0xa7, 0xe3,		/* loadDisplay */
	0x1b, 0x54, 0x02, 0x06, 0x1e, 0x04,	/* escTstxackrscot */
	0xa3, 0x80, 0x28, 0x0f	/* terminal lamp flash 0T7 green */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayCA1Flash_NEW[] = {
	0x1d,			/* Len 29 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xac, 0xe3, 0x30, 0x33, 0x35, 0x35, 0x34, 0x32, 0x32, 0x33, 0x30, 0x31, 0x32,	/* loadDisplay? 03554223012 total len=11[6] */
	0xa7, 0xe3,		/* loadDisplay */
	0x1b, 0x54, 0x02, 0x0e, 0x14, 0x0f,	/* escTstxsodc4si */
	0xa3, 0x80, 0x28, 0x0f	/* terminal lamp flash 0T7 green */
};
static const int CCMS_vdtUpdate_loadDisplayCA1Flash_NEW_Length = sizeof(CCMS_vdtUpdate_loadDisplayCA1Flash_NEW);

static const unsigned char CCMS_vdtUpdate_loadDisplayCA1Off[] = {
	0x15,			/* Len 21 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xab, 0xe3,		/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[; */
	0x1b, 0x5b, 0x02, 0x4b,			/* esc[stxK */
	0x40,			/* ringerChange = Off */
	0xa3, 0x80, 0x20, 0x0f	/* terminal lamp dark 0T7 green */
};

/* Maximum name length = 14+13 = 27 chars */
static const unsigned char CCMS_vdtUpdate_ringerOffDisplayName[] = {
	0x14,			/* Len 20 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0x40,			/* ringerChange = ringerChange = Off */
	0xae, 0xe3,		/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[; */
	0x1b, 0x5b, 0x02, 0x4b, 0x01, 0x3d, 0x54	/* esc[stxKsoh=T[19] */
};
static const int CCMS_vdtUpdate_ringerOffDisplayName_Length = sizeof(CCMS_vdtUpdate_ringerOffDisplayName);

static const unsigned char CCMS_vdtUpdate_loadDisplayFinish[] = {
	0x0c,			/* Len 16 */
	0x38, 0x11, 0x20,
	0xa7, 0xe3,		/* loadDisplay */
	0x1b, 0x54, 0x02, 0x06, 0x1e, 0x04,	/* escTstxackrscot */
};

static const unsigned char CCMS_vdtUpdate_ringerOffCA1Steady[] = {
	0x09,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0x40,			/* ringerChange = Off */
	0xa3, 0x80, 0x2f, 0x0f	/* terminal lamp steady 0T7 green */
};

static const unsigned char CCMS_vdtUpdate_ringerOffCA1SteadyNEW[] = {
	0x0a,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0x89,			/* Off-hook alert */
	0x40,			/* ringerChange = Off */
	0xa3, 0x80, 0x2f, 0x0f	/* terminal lamp steady 0T7 green */
};

/*
	0xAx - low bits [0-3] contains actual length for display/terminal
	0x80
	0x40
	0x20
	0x10
*/
/* NEW */
static const unsigned char CCMS_vdtUpdate_loadDisplayRingerOff[] = {
/*	0x13,			 Len 19 */
	0x16,
	0x38, 0x11, 0x20,	/* 81A0501 */
/**/
	0xa2, 0x80, 0x05, /* ? */
	0x40,				/* ringerChange = Off */
	0xad, 0xe3,			/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48, /* esc[;H */
	0x1b, 0x5b, 0x02, 0x4b, 0x01, 0x3d	/* esc[stxKsoh= */
};

static const unsigned char CCMS_vdtUpdate_displayControlCA1Steady[] = {
	0x0c,			/* Len 12 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa3, 0x83, 0x04, 0x02,	/* displayControl timerOff */
	0xa3, 0x80, 0x2f, 0x0f	/* terminal lamp steady 0T7 green */
};

static const unsigned char CCMS_vdtUpdate_displayControlCA1SteadyNEW[] = {
	0x0d,			/* Len 13 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0x89,
	0xa3, 0x83, 0x04, 0x02,	/* displayControl timerOff */
	0xa3, 0x80, 0x2f, 0x0f	/* terminal lamp steady 0T7 green */
};


static const unsigned char CCMS_vdtUpdate_loadDisplayControlTADial[] = {
	0x1a,			/* Len 26 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xad, 0xe3,			/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48, /* esc[;H */
	0x1b, 0x5b, 0x02, 0x4b, 0x01, 0x3d, /* esc[stxKsoh= */
	0xa3, 0x83, 0x04, 0x41,		/* displayControl Normal */
	0xa3, 0x80, 0x18, 0x00		/* terminal toneApplication Dial */
};

static const unsigned char CCMS_vdtUpdate_TARingbackRemoved[] = {
	0x08,			/* Len */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xa3, 0x80, 0x18, 0x07		/* terminal toneApplication Ringback removed */
};

static const unsigned char CCMS_vdtUpdate_Digit1[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x01		/* Dialpad button 1 */
};

static const unsigned char CCMS_vdtUpdate_Digit2[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x02		/* Dialpad button 2 */
};

static const unsigned char CCMS_vdtUpdate_Digit3[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x03		/* Dialpad button 3 */
};

static const unsigned char CCMS_vdtUpdate_Digit4[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x04		/* Dialpad button 4 */
};

static const unsigned char CCMS_vdtUpdate_Digit5[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x05		/* Dialpad button 5 */
};

static const unsigned char CCMS_vdtUpdate_Digit6[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x06		/* Dialpad button 6 */
};

static const unsigned char CCMS_vdtUpdate_Digit7[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x07		/* Dialpad button 7 */
};

static const unsigned char CCMS_vdtUpdate_Digit8[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x08		/* Dialpad button 8 */
};

static const unsigned char CCMS_vdtUpdate_Digit9[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x09		/* Dialpad button 9 */
};

static const unsigned char CCMS_vdtUpdate_Digit0[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x0a		/* Dialpad button 0 */
};

static const unsigned char CCMS_vdtUpdate_DigitStar[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x0b		/* Dialpad button "*" */
};

static const unsigned char CCMS_vdtUpdate_DigitPound[] = {
	0x05,			/* Len */
	0x38, 0x00,		/* 81A050? */
	0x7f, 0x0c		/* Dialpad button "#" */
};

/* NEW */
static const unsigned char CCMS_vdtUpdate_loadDisplayDisconnectCA1OFF[] = {
/* 0x18,			 Len 24 */
	0x16,
	0x38, 0x11, 0x20,	/* 81A0501 */
	0x84,				/* Aux control disconnect */
	0x40,				/* Ringer OFF 2021/03/24 */
	0xab, 0xe3, 		/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[;H */ 
	0x1b, 0x5b, 0x02, 0x4b,				/* esc[stxK */
	0xa3, /* ? */
	0x80, 0x20, 0x0f,		/* terminal lamp dark 0T7 green */
/*	0x80, 0x20, 0x0e		 terminal lamp dark 0T7 red */
};

static const unsigned char CCMS_vdtUpdate_loadDisplayCA1RedSteady[] = {
	0x14,				/* Len 20 */
	0x38, 0x11, 0x20,	/* 81A0501 */
	0xab, 0xe3,			/* loadDisplay */
	0x1b, 0x5b, 0x00, 0x3b, 0x00, 0x48,	/* esc[;H */ 
	0x1b, 0x5b, 0x02, 0x4b,				/* esc[stxK */
	0xa3, 0x80, 0x2f, 0x0e	/* terminal lamp steady 0T7 red */
};

static const unsigned char CCMS_vdtUpdate_selectSpeaker[] = {
	0x05,				/* Len 06 */
	0x38, 0x00, 0x81, 0x02	/* Speaker ON??? */
};

#endif