// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// GkAuthorize.cxx Authorize gateways for access to different prefixes
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


#include <stdio.h>

#include <ptlib.h>
#include <ptlib/sockets.h>

#include <string.h>

#include "GkAuthorize.h"
#include "ptlib.h"
#include "Toolkit.h"
#include "RasTbl.h"

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = GWRESTRICTIONS_H;
#endif /* lint */

static const char* const loghead="AUTHORIZE";
static const char* const section="GkAuthorize";
static const char* const prfflag="prf:";
static const char* const allowflag="allow";
static const char* const denyflag="deny";
static const char* const ipflag="ipv4:";
static const char* const policy="default";


GkAuthorize::GkAuthorize(GkStatus* s)
{
	GkStatusThread=s;
	prfl=(PString((char *)prfflag)).GetLength();
	ipfl=(PString((char *)ipflag)).GetLength();
	keys = GkConfig()->GetKeys(section);
	if(!keys.GetSize()){dpolicy=TRUE;no_config=TRUE;return;}
	no_config=FALSE;
	//default policy
	dpolicy=(GkConfig()->GetString(section,policy,allowflag).ToLower()).Compare((PString)allowflag)==PObject::EqualTo?TRUE:FALSE;
}

BOOL GkAuthorize::checkgw(const H225_AdmissionRequest & arq, const endptr & RequestingEP, const endptr & CalledEP)
{
	//there is no GkAuthorize section in the config file
	if(no_config==TRUE)return TRUE;
	BOOL desi=dpolicy;

	//we check if the call is already authorized

	callptr Ex_call;
	if(arq.HasOptionalField(H225_AdmissionRequest::e_callIdentifier) &&
	   (Ex_call=CallTable::Instance()->FindCallRec(arq.m_callIdentifier)))
	{
		PTRACE(4,"found existing call no " << Ex_call->GetCallNumber() );
		return TRUE;
	}

#ifdef CHECK_FOR_ALIAS0
	PAssert(FALSE, "GkAuthorize::checkgw called with arq.m_destinationInfo[0]");
#endif
	switch((arq.m_destinationInfo[0]).GetTag())
	{
	case H225_AliasAddress::e_dialedDigits: return prefixip(arq,RequestingEP,CalledEP);
	default:
		PString msg(PString::Printf,"%s|%s||||UnknownDestinationType" GK_LINEBRK,loghead,desi==FALSE?"DENY":"ALLOW");
		PTRACE(2,msg);
		GkStatusThread->SignalStatus(msg);
		return desi;
	}
	return desi;
}

BOOL GkAuthorize::prefixip(const H225_AdmissionRequest & arq,const endptr & RequestingEP, const endptr & CalledEP)
{
	PINDEX maxprf=keys.GetSize();
	BOOL desi=dpolicy;

	if(!RequestingEP) {
		PString msg("RequestingEP is NULL\r\n");
		PTRACE(1,msg);
		GkStatusThread->SignalStatus(msg);
		return desi;
	}
	if(!CalledEP) {
		PString msg("CalledEP is NULL\r\n");
		PTRACE(1,msg);
		GkStatusThread->SignalStatus(msg);
		return desi;
	}

	H225_TransportAddress_ipAddress srcipaddr;
	H225_TransportAddress_ipAddress dstipaddr;
	int srcaddrfound=0;

	if(arq.HasOptionalField(H225_AdmissionRequest::e_srcCallSignalAddress))	{
		srcipaddr=(H225_TransportAddress_ipAddress)arq.m_srcCallSignalAddress;
		srcaddrfound=1;
	}
	else if(arq.m_answerCall!=TRUE)	{
		srcipaddr=(H225_TransportAddress_ipAddress)RequestingEP->GetCallSignalAddress();
		srcaddrfound=1;
	}
	dstipaddr=(H225_TransportAddress_ipAddress)CalledEP->GetCallSignalAddress();

	PINDEX lp=0;
#ifdef CHECK_FOR_ALIAS0
	PAssert(FALSE, "GkAuthorize::prefixip called with arq.m_destinationInfo[0]");
#endif
	PString ta= ((PASN_IA5String&)((arq.m_destinationInfo[0])).GetObject()).GetValue();
	PINDEX i;
	for (i = 0; i < keys.GetSize(); i++)
	{
		PINDEX pp;
		if((pp=chkrule(prfflag,keys[i],PREFIX))!=P_MAX_INDEX)
		{

			PString prf=((keys[i]).Mid(pp+prfl)).Trim();
			PTRACE(4,"ConfigPrefix:" << prf << GK_LINEBRK);
			//            cout << prf <<"\n";
			if(ta.Find(prf)==0)
			{
				if(prf.GetLength()>=lp)
				{
					lp=prf.GetLength();
					maxprf=i;
				}
			}
			else if(prf.Find("ALL")==0)
			{
				if(!lp)
				{
					maxprf=i;
				}
			}
		}//if((keys

	}//for
	if(maxprf== keys.GetSize())
	{
		//prefix was not found
		PString msg(PString::Printf,"%s|%s|%d.%d.%d.%d:ipv4|%s:dialedDigits|%d.%d.%d.%d:ipv4|UnknownPrefix\r\n",loghead,desi==FALSE?"DENY":"ALLOW",
			    srcipaddr.m_ip[0],
			    srcipaddr.m_ip[1],
			    srcipaddr.m_ip[2],
			    srcipaddr.m_ip[3],(const char*)ta,dstipaddr.m_ip[0],dstipaddr.m_ip[1],dstipaddr.m_ip[2],dstipaddr.m_ip[3]);
		PTRACE(2,msg);
		GkStatusThread->SignalStatus(msg);
		return desi;
	}
	PTRACE(2,"Prefix " << (keys[maxprf]).Mid(prfl).Trim()
	       <<" is found for destination " << ta );

	//now we'll check rules for destination
	int rul=TRUE;
	unsigned masklong=0;
	unsigned ms;

	if(srcaddrfound) {
		for(i=maxprf+1;i<keys.GetSize();i++) {
			if(chkrule(prfflag,keys[i],PREFIX)!=P_MAX_INDEX)
				break;
			else if(chkrule(allowflag,keys[i],RULE)!=P_MAX_INDEX) {
				PTRACE(4,"Allow: " <<  keys[i] << GK_LINEBRK);
				rul=TRUE;
			} else if(chkrule(denyflag,keys[i],RULE)!=P_MAX_INDEX) {
				PTRACE(4,"Deny: " << keys[i] << GK_LINEBRK);
				rul=FALSE;
			}//if(chkrule(denyflag,keys[i],RULE)==TRUE)
			PINDEX np;
			if((np=chkrule(ipflag,keys[i],FLAG))!=P_MAX_INDEX) {
				PString net;
				//PINDEX np=(keys[i]).Find(ipflag);
				np+=ipfl;
				net=(keys[i])(np,(keys[i]).FindOneOf(" \t",np)).Trim();
				//		cout << "NET: " << net << "\n";
				PINDEX slash=net.Find("/");
				PString ip;
				PString mask;
				if((slash!=P_MAX_INDEX) && (slash!=0)) {
					ip=net(0,slash-1);
					mask=net(slash+1,net.GetLength()-1);
				} else {
					ip=net;
					mask="32";
				}
				if(ip.Find("ALL")==0) {
					ip="0";
					mask="0";
				}

				PTRACE(4, ip << "/" << mask << GK_LINEBRK);

				AddrMatrix ip_dig;
				AddrMatrix mask_dig;

				if(mask.Find(".")!=P_MAX_INDEX)
					//mask contains dots
				{
					dottochar(mask,mask_dig);

					//now we are calculating mask length
					unsigned j;
					ms=0;
					for(j=0;j<4;j++)
					{
						if(mask_dig[j]==255)
						{
							ms+=8;
						}
						else
						{
							switch(mask_dig[j])
							{
							case 0:
								break;
							case 128:
								ms+=1;
								break;
							case 192:
								ms+=2;
								break;
							case 224:
								ms+=3;
								break;
							case 240:
								ms+=4;
								break;
							case 248:
								ms+=5;
								break;
							case 252:
								ms+=6;
								break;
							default:
								ms=32;
								break;
							}
							break;
						}
					} //for
				} //if(mask.Find(".")!=P_MAX_INDEX)
				else
				{
					unsigned j;
					ms=mask.AsUnsigned();

					ms=(ms>32)?32:ms;

					unsigned k=ms;

					for(j=0;k&&(j<4);j++)
					{
						mask_dig[j]=~0;
						if(k>=8)
						{
							k-=8;
						}
						else
						{
							mask_dig[j]<<=8-k;
							k=0;
						}
					}
				} //if(mask.Find(".")!=P_MAX_INDEX) else
				dottochar(ip,ip_dig);
				//we try to determine if callsrcaddress is from this prefix
				ip_dig[0]&=mask_dig[0];
				ip_dig[1]&=mask_dig[1];
				ip_dig[2]&=mask_dig[2];
				ip_dig[3]&=mask_dig[3];
				H225_TransportAddress_ipAddress srcip=srcipaddr;
				srcip.m_ip[0]&=mask_dig[0];
				srcip.m_ip[1]&=mask_dig[1];
				srcip.m_ip[2]&=mask_dig[2];
				srcip.m_ip[3]&=mask_dig[3];

				if((ip_dig[0]==srcip.m_ip[0])&&(ip_dig[1]==srcip.m_ip[1])&&(ip_dig[2]==srcip.m_ip[2])&&
				   (ip_dig[3]==srcip.m_ip[3]))
				{
//					cout << "Eq " << "Ms: " << ms << " Masklong: " << masklong << "\n";
					if(ms>=masklong)
					{
						masklong=ms;desi=rul;
						PTRACE(4,(PString)"Set Result to " << (PString)((desi==TRUE)?"Allowed":"Denyed") << (PString)GK_LINEBRK);
					}
				}

			} //if((np=chkrule(ipflag,keys[i],FLAG))!=P_MAX_INDEX)
		} //for(i=maxprf+1;i<keys.GetSize();i++)
		PString msg(PString::Printf,"%s|%s|%d.%d.%d.%d:ipv4|%s:dialedDigits|%d.%d.%d.%d:ipv4|OK\r\n",loghead,desi==FALSE?"DENY":"ALLOW",
			    srcipaddr.m_ip[0],
			    srcipaddr.m_ip[1],
			    srcipaddr.m_ip[2],
			    srcipaddr.m_ip[3],(const char*)ta,dstipaddr.m_ip[0],dstipaddr.m_ip[1],dstipaddr.m_ip[2],dstipaddr.m_ip[3]);
		PTRACE(2,msg);
		GkStatusThread->SignalStatus(msg);
	} //if(srcaddrfound)
	else {
		PTRACE(4,(PString)"srcCallSignalAddress is unknown returning " << (PString)((desi==TRUE)?"TRUE":"FALSE") << "\r\n");
	}
	return desi;
} //GkAuthorizeions::checkgw

PINDEX GkAuthorize::chkrule(const PString & orstr, const PString & src, REGEXMOD mode=RULE)
{
	PString re;

	switch(mode)
	{
	case RULE:
		re="^[ \\t]*" + orstr + "[ \\t]\\{1,\\}";
		break;
	case FLAG:
		re="[ \\t]\\{1,\\}" + orstr;
		break;
	case PREFIX:
		re="^[ \\t]*" + orstr;
		break;
	default:
		return P_MAX_INDEX;
	}

	PINDEX rp;
	if((rp=src.FindRegEx(re))!=P_MAX_INDEX) return src.Find(orstr,rp);
	return P_MAX_INDEX;
} //GkAuthorize::chkrule

int GkAuthorize::dottochar(const PString & s, AddrMatrix & u)
{
	PINDEX i;
	PINDEX pnt;
	for(i=0,pnt=0;i<4;i++)
	{
		PINDEX r=s.Find('.',pnt);
		r=(r==P_MAX_INDEX)?s.GetLength():r;
		u[i]=(s.Mid(pnt,r-pnt)).AsUnsigned();
		if(r==s.GetLength())break;
		pnt=r+1;
	}

	return i;

} //GkAuthorize::dottochar

unsigned char & AddrMatrix::operator [](const PINDEX i)
{
	return matr[i];
} //ddrMatrix::operator []

GkAuthorize::~GkAuthorize()
{
//    if(GkStatusThread!=NULL) delete GkStatusThread;
}
