// Toolkit_Mediaways.h
// author:	Torsten Will, mediaWays
// initial revision: 1999/12/27

#ifndef _toolkit_mediaways_h__
#define _toolkit_mediaways_h__

#include "Toolkit.h"


class Toolkit_Mediaways : public Toolkit {
	/// define an abbrevation
	typedef Toolkit inherited;
	
 public: // con- and destructing
	explicit Toolkit_Mediaways();

	virtual const PString GetName() const { return "mways"; }

 public: // virtual tools
	/** Takes alias and if it is a e164 number it looks in the 
	 * config and maybe rewrites the destinationInfo[0].
	 * @see Gatekeeper.ini
	 */
	virtual BOOL RewriteE164(H225_AliasAddress &alias);
	/// true if #s# has changed
	virtual BOOL RewritePString(PString &s);
	
 public: // static tools
	/** A c-string (#char*#) hash function that considers the
	 * whole string #name# ending with #\0#.
	 */
	inline static unsigned long HashCStr(const unsigned char *name) ;
	
 public: // accessors
	static Toolkit* Instance();
	
 protected: // fields
	/** e164s starting with this string are examined further for rewrting. */
	const PString  m_RewriteFastmatch;
	BOOL           m_EmergencyAccept;
	
};


/*
 *  Inline Section
 */


inline
unsigned long 
Toolkit_Mediaways::HashCStr(const unsigned char *name) 
{
	register unsigned long h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		if ( (g = (h & 0xf0000000)) ) h ^= g >> 24;
		h &= ~g;
	}
	return h;
}



#endif



