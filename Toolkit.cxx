//////////////////////////////////////////////////////////////////
//
// Toolkit base class for the OpenGK
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	991227  initial version (Torsten Will, mediaWays)
//
//////////////////////////////////////////////////////////////////

#include "Toolkit.h"
#include "ANSI.h"

#include <ptlib.h>
#include "h323pdu.h"


Toolkit*  Toolkit::m_Instance = NULL;
PMutex    Toolkit::m_CreationLock;
PFilePath Toolkit::m_ConfigFilePath("gatekeeper.ini");
PString   Toolkit::m_ConfigDefaultSection("Gatekeeper::Main");
PConfig*  Toolkit::m_Config = NULL;


Toolkit* Toolkit::Instance()
{
	if (m_Instance == NULL)
	{
		m_CreationLock.Wait();
		if (m_Instance == NULL)
			m_Instance = new Toolkit();
		m_CreationLock.Signal();
	}
	
	return m_Instance;
}


Toolkit::Toolkit()
	: m_RewriteFastmatch(Config()->GetString("RasSvr::RewriteE164","Fastmatch", ""))
{
}


PConfig* Toolkit::Config()
{ 
	if (m_Config == NULL) {
		m_Config = new PConfig(m_ConfigFilePath, m_ConfigDefaultSection);
	}
	
	return m_Config; 
}


PConfig* Toolkit::SetConfig(const PFilePath &fp, const PString &section)
{ 
    m_ConfigFilePath = fp;
	m_ConfigDefaultSection = section;

	return ReloadConfig();
}


PConfig* Toolkit::ReloadConfig()
{
	if (m_Config != NULL) 
		delete m_Config;
	
	m_Config = new PConfig(m_ConfigFilePath, m_ConfigDefaultSection);
	
	return m_Config; 
}


BOOL Toolkit::MatchRegex(const PString &str, const PString &regexStr)
{
	PINDEX pos=0;
	PRegularExpression regex(regexStr, PRegularExpression::Extended);
	if(regex.GetErrorCode() != PRegularExpression::NoError) {
		PTRACE(2, "Errornous '"<< regex.GetErrorText() <<"' compiling regex: " << regexStr);
		return FALSE;
	}
	if(!regex.Execute(str, pos)) {
		PTRACE(5, "Gk\tRegex '"<<regexStr<<"' did not match '"<<str<<"'");
		return FALSE;
	}
	return TRUE;
}



BOOL  
Toolkit::RewriteE164(H225_AliasAddress &alias)
{ 
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits) 
		return FALSE;
	
	PString oldE164 = H323GetAliasAddressString(alias);
	PString newE164 = oldE164;

	BOOL changed = RewritePString(newE164);
	if (changed) {
		H323SetAliasAddress(newE164, alias);
		PTRACE(5, "\tRewriteE164: " << oldE164 << " to " << newE164);
	}
	
	return changed;
}



BOOL 
Toolkit::RewritePString(PString &s)
{
	BOOL changed = FALSE;
	BOOL do_rewrite = FALSE; // marker if a rewrite has to be done.

	// startsWith?
	if(strncmp(s, m_RewriteFastmatch, m_RewriteFastmatch.GetLength()) != 0)
		return changed;

	// get the number to rewrite from config entry
	PString t = Config()->GetString("RasSvr::RewriteE164",s, "");
	if(t != "") {
		// number found in config exactly => rewrite it.
		// #t# is just right now!
		do_rewrite = TRUE;
	} else {
		// not found directly, try a prefix match through all keys
		const PStringList &keys = Config()->GetKeys("RasSvr::RewriteE164");
		for(PINDEX i=0; i < keys.GetSize(); i++) {
			if(s.Find(keys[i]) == 0) { // startWith
				// Rewrite to #t#. Append the suffix, too.
				// old:  01901234999
				//               999 Suffix
				//       0190        Fastmatch
				//       01901234    prefix, Config-Rule: 01901234=0521321
				// new:  0521321999    
				t = Config()->GetString("RasSvr::RewriteE164",keys[i], "");

				// multiple targets possible
				if (t != "") {
					const PStringArray ts = t.Tokenise(",:;&|\t ", FALSE);
					if(ts.GetSize() > 1) {
						PINDEX i = rand()%ts.GetSize();
						PTRACE(5, "\tRewritePString: randomly chosen [" << i << "] of " << t << "");
						t = ts[i];
					}
				}
				
				// append the suffix
				t += s(t.GetLength(),10000); // 10000 is used for the rest of the string

				do_rewrite = TRUE;
				break;
			}
		}
	}
	
	// 
	// Do the rewrite. 
	// @param #t# will be written to #s#
	//
	if(do_rewrite) {
		PTRACE(2, "\tRewritePString: " << s << " to " << t << "");
		s = t;
		changed = TRUE;
	}
	
	return changed;
}


const PString 
Toolkit::GKName() 
{
  return Config()->GetString("Gatekeeper::Main", "Name", "OpenH323GK");
}



// a int to print
#ifdef P_PTHREADS
static const int INT_PTHREADS = 1;
#else
static const int INT_PTHREADS = 0;
#endif

const PString 
Toolkit::GKVersion() 
{
	return PString(PString::Printf,
				   "Gatekeeper(%s) Version(%s) Ext(pthreads=%d) Build(%s, %s) Sys(%s %s %s)\r\n",
				   (const unsigned char*)(PProcess::Current().GetManufacturer()),
				   (const unsigned char*)(PProcess::Current().GetVersion(TRUE)),
				   INT_PTHREADS,
				   __DATE__, __TIME__,
				   (const unsigned char*)(PProcess::GetOSName()),
				   (const unsigned char*)(PProcess::GetOSHardware()),
				   (const unsigned char*)(PProcess::GetOSVersion())
				   );
}



int
Toolkit::GetInternalExtensionCode( const unsigned &country, 
								   const unsigned &extension, 
								   const unsigned &manufacturer) const 
{
	switch(country) {
	case t35cOpenOrg: 
		switch(manufacturer) {
		case t35mOpenOrg:
			switch(extension) {
				case t35eFailoverRAS: return iecFailoverRAS;
			}
		}
	}

	// default for all other cases
	return iecUnknown;
}



BOOL 
Toolkit::AsBool(const PString &str) 
{
	if (str.GetLength() < 1) return FALSE;
	const unsigned char c = tolower(str[0]);
	return ( c=='t' || c=='1' || c=='y' || c=='a' );
}
