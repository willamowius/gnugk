//////////////////////////////////////////////////////////////////
//
// GkQ931.h -- wrapper around openH323 class Q931
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// initial author:	Torsten Will, mediaWays
// initial revision: 2000/01/12
//
//////////////////////////////////////////////////////////////////

#ifndef _gkq931_h__
#define _gkq931_h__

#include <q931.h>

class GkQ931 : public Q931 {
 private: // C++-helpers
	PCLASSINFO(GkQ931, Q931);
	typedef Q931 inherited;
	GkQ931(const GkQ931&); /*  {}  */

  public:
    GkQ931& operator=(const GkQ931 &abc)
    {
		return (GkQ931&) inherited::operator=(abc); 
	}
	
    GkQ931() : Q931()
    { 
	}

    enum NumberingPlanCodes
    {
		UnknownPlan          = 0x00,
		ISDNPlan             = 0x01,
		DataPlan             = 0x03,
		TelexPlan            = 0x04,
		NationalStandardPlan = 0x08,
		PrivatePlan          = 0x09,
		ReservedPlan         = 0x0f
	};

    enum TypeOfNumberCodes
    {
		UnknownType          = 0x00,
		InternationalType    = 0x01,
		NationalType         = 0x02,
		NetworkSpecificType  = 0x03,
		SubscriberType       = 0x04,
		AbbreviatedType      = 0x06,		
		ReservedType         = 0x07
	};

    void SetCalledPartyNumber(const PString & number,
							  unsigned plan = 1, unsigned type = 0) 
		{ inherited::SetCalledPartyNumber(number, plan, type); }
};

#endif















