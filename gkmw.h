//////////////////////////////////////////////////////////////////
//
// gkmw.h gatekeeper process, mediaWays extensions
//
// (c) mediaWays, Verl, Germany
//
// $Log$
// Revision 2.4  2000/02/16 10:19:39  storm
// tut
//
// Revision 2.4  2000/02/14 17:50:49  towi
// - structured code for FailoverForwarding and make it work better
//
// Revision 2.3  2000/02/11 16:21:58  towi
// * Added simple GkStatus authentication
//
// Revision 2.1  2000/02/10 11:33:25  towi
// - final merge in linux
//
// Revision 2.0  2000/02/09 15:07:57  towi
// X
//
// Revision 1.1  2000/01/31 12:25:12  towi
// * Diveded source in OpenGK and GKMW
//
//
//////////////////////////////////////////////////////////////////


#ifndef _gkmw_h
#define _gkmw_h

#include "gk.h"

class Gatekeeper_Mediaways : public Gatekeeper
{
	PCLASSINFO(Gatekeeper_Mediaways, Gatekeeper);
	typedef Gatekeeper inherited;
 public:

	Gatekeeper_Mediaways
		(const char * manuf = "Mediaways", 
		 const char * name = "Gatekeeper")
		: Gatekeeper(manuf, name) 
		{ }

 protected:

	virtual BOOL InitToolkit(const PArgList &args);

};

#endif
 
