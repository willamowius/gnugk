//////////////////////////////////////////////////////////////////
//
// Toolkit class for the MediawaysGK
//
// $COPYRIGHT_MWAYS$
//
// History:
// 	991227  initial version (Torsten Will, mediaWays)
//
//////////////////////////////////////////////////////////////////

#include "Toolkit_Mediaways.h"

#include "gk.h"
#include "ANSI.h"

#include <ptlib.h>
#include <stdio.h>


Toolkit_Mediaways::Toolkit_Mediaways()
	: m_RewriteFastmatch(Config()->GetString("RasSvr::RewriteE164","Fastmatch", ""))
{
}

Toolkit*
Toolkit_Mediaways::Instance()
{
	if (m_Instance == NULL)
	{
		m_CreationLock.Wait();
		if (m_Instance == NULL)
			m_Instance = new Toolkit_Mediaways();
		m_CreationLock.Signal();
	}
	
	return m_Instance;
}



BOOL
Toolkit_Mediaways::RewriteE164(H225_AliasAddress &alias) 
{
	if (alias.GetTag() != H225_AliasAddress::e_e164) 
		return FALSE;
	
	PString oldE164 = ((PASN_IA5String&)(alias).GetObject()).GetValue();
	PString newE164 = oldE164;

	BOOL changed = RewritePString(newE164);
	if(changed) {
		((PASN_IA5String&)(alias).GetObject()).SetValue(newE164);
		PTRACE(5, "\tRewriteE164: " << oldE164 << " to " << newE164 << "");
	}
	
	return changed;
}




BOOL
Toolkit_Mediaways::RewritePString(PString &s) 
{	
	BOOL changed = inherited::RewritePString(s);

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
				// Do rewrite to #t#. Append the suffix too.
				// old:  01901234999
				//               999 Suffix
				//       0190        Fastmatch
				//       01901234    prefix, Config-Rule: 01901234=0521321
				// new:  0521321999    
				t = 
					Config()->GetString("RasSvr::RewriteE164",keys[i], "")
					+ s(keys[i].GetLength(),10000); // 10000 is used for the rest of the string
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




