// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// GkAuthorize.h Authorize gateways for access to different prefixes
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      020114  initial version (Michael Rubashenkkov)
//
//////////////////////////////////////////////////////////////////

#ifndef __GWRESTRICTIONS_H__
#define __GWRESTRICTIONS_H__

#include "h225.h"
#include "h323.h"
#include "GkStatus.h"
#include "RasTbl.h"
class AddrMatrix
{
    unsigned char matr[4];

    public:
    unsigned char & operator[](const PINDEX);

    AddrMatrix(void)
    {
	matr[0]=0;matr[1]=0;matr[2]=0;matr[3]=0;
    }
};

class GkAuthorize:public PObject
{
    PCLASSINFO(GkAuthorize, PObject)

    private:

    BOOL dpolicy;
    BOOL no_config;
    PStringList keys;
    PINDEX prfl,ipfl;

    enum REGEXMOD{RULE,FLAG,PREFIX};

    GkStatus* GkStatusThread;

    BOOL prefixip(const H225_AdmissionRequest & arq,const endptr & RequestingEP, const endptr & CalledEP);

    protected:
    PINDEX chkrule(const PString &,const PString &,REGEXMOD);
    int dottochar(const PString &, AddrMatrix &);

    public:
    GkAuthorize(GkStatus* s);
    ~GkAuthorize();

    BOOL checkgw(const H225_AdmissionRequest & arq,const endptr & RequestingEP, const endptr & CalledEP);
};

#endif
