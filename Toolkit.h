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

#ifndef _toolkit_h__
#define _toolkit_h__

#include <ptlib.h>
#include "h225.h"
#include "singleton.h"


class Toolkit : public Singleton<Toolkit>
{
 public: // con- and destructing
	explicit Toolkit() : m_Config(NULL) {}
	virtual ~Toolkit();

	/// returns #basic# for
	virtual const PString GetName() const { return "basic"; }

 public: // virtual tools
	/// maybe modifies #alias#. returns true if it did
	virtual BOOL  RewriteE164(H225_AliasAddress &alias);

	virtual BOOL RewritePString(PString &s);

 public: // accessors
	/** Accessor and 'Factory' to the static Toolkit. 
	 * If you want to use your own Toolkit class you have to
	 * overwrite this method and ensure that your version is 
	 * called first -- before any other call to #Toolkit::Instance#.
	 * Example: 
	 * <pre>
	 * class MyToolkit: public Toolkit {
	 *  public: 
	 *   static Toolkit& Instance() {
	 *	   if (m_Instance == NULL) m_Instance = new MyToolkit();
	 *     return m_Instance;
	 *   }
	 * };
	 * void main() {
	 *   MyToolkit::Instance();
	 * }
	 * </pre>
	 */

	/** Accessor and 'Factory' for the global (static) configuration. 
	 * With this we are able to implement out own Config-Loader 
	 * in the same way as #Instance()#. And we can use #Config()# 
	 * in the constructor of #Toolkit# (and its descentants).
	 */
	PConfig* Config(); 
	PConfig* Config(const char *); 

	/** Sets the config that the toolkit uses to a given config.
	 *  A prior loaded Config is discarded. 
	 */
	PConfig* SetConfig(const PFilePath &fp, const PString &section);

	PConfig* ReloadConfig();

	/// reads name of the running instance from config
	static const PString GKName();

	/// returns an identification of the binary
	static const PString GKVersion();

	/** #f# is called for each element
	 * and is of the style #void f(const element &e, void *param)#.
	 * @see C++-Stl #for_each#. 
	 * @see #H323RasSrv::UnregisterAllEndpoints#
	 */
	template <class InputIterator, class Function>
		static Function for_each_with(InputIterator first, InputIterator last, Function f, void* param);

	template <class InputIterator, class Function>
		static Function for_each_with2(InputIterator first, InputIterator last, Function f, 
									   void* p1, void* p2);

	/** simplify PString regex matching.
	 * @param str String that should match the regex
	 * @param regexStr the string which is compiled to a regex and executed with #regex.Execute(str, pos)#
	 * @return TRUE if the regex matched and FALSE if not or any error case.
	 */
	static BOOL MatchRegex(const PString &str, const PString &regexStr);

	/** returns the #BOOL# that #str# represents. 
	 * Case insensitive, "t...", "y...", "a...", "1" are #TRUE#, all other values are #FALSE#.
	 */
	static BOOL AsBool(const PString &str);


	/** you may add more extension codes in descendant classes. This codes will not be transferred
	 * or something it will be the return code of some methods for handling switches easy. */
	enum {
		iecUnknown     = -1,  /// internal extension code for an unknown triple(cntry,ext,manuf)
		iecFailoverRAS  = 1,   /// i.e.c. for "This RQ is a failover RQ" and must not be answerd.
		iecUserbase    = 1000 /// first guaranteed unused 'iec' by OpenGK Toolkit.
	};
	/** t35 extension or definitions as field for H225_NonStandardIdentifier */
	enum {
		t35cOpenOrg = -1,       /// country code for the "Open Source Organisation" Country
		t35mOpenOrg = 4242,     /// manufacurers code for the "Open Source Organisation"
		t35eFailoverRAS = 1001  /// Defined HERE! 
	};
	/** If the triple #(country,extension,manufacturer)# represents an 
	 * extension known to the OpenGK this method returns its 'internal extension code' 
	 # #iecXXX' or #iecUnknow# otherwise.
	 *
	 * Overwriting methods should use a simlilar scheme and call
	 * <code>
	 * if(inherited::OpenGKExtension(country,extension,menufacturer) == iecUnknown) {
	 *   ...
	 *   (handle own cases)
	 *   ...
	 * }
	 * </code>
	 * This results in 'cascading' calls until a iec!=iecUnkown is returned.
	 */
	virtual int GetInternalExtensionCode(const unsigned &country, 
										 const unsigned &extension, 
										 const unsigned &manufacturer) const;
	

	int GetInternalExtensionCode(const H225_H221NonStandard& data) const {
		return GetInternalExtensionCode(data.m_t35CountryCode,
										data.m_t35Extension,
										data.m_manufacturerCode);
	}

	/** A c-string (#char*#) hash function that considers the
	 * whole string #name# ending with #\0#.
	 */
	inline static unsigned long HashCStr(const unsigned char *name) ;

 protected:
	PFilePath m_ConfigFilePath;
	PString   m_ConfigDefaultSection;
	PConfig*  m_Config;

	/** e164s starting with this string are examined further for rewriting. */
	PString   m_RewriteFastmatch;
	BOOL      m_EmergencyAccept;

 private:
	PFilePath m_tmpconfig;
};


/** this protects the block in where it is declared. 
 * It automatically waits when the block is entered and signals
 * when it is leaved (in any way). You have to use a existing mutex
 */
class GkProtectBlock
{
private: /* make sure no call to this constructors is generated -> cause link errors */
    GkProtectBlock(const GkProtectBlock&); /*  {}  */
    GkProtectBlock& operator=(const GkProtectBlock &abc); /* { return *this; }  */
	GkProtectBlock(); /* {} */
protected:
	PMutex& mutex;
public:
	GkProtectBlock(PMutex &a_mutex) : mutex(a_mutex) { mutex.Wait(); }
	~GkProtectBlock() { mutex.Signal(); }
};


//
// inlines
//

template <class InputIterator, class Function>
inline Function 
Toolkit::for_each_with(InputIterator first, InputIterator last, Function f, void* param)
{
  for ( ; first != last; ++first)
    f(*first, param);
  return f;
}


template <class InputIterator, class Function>
inline Function 
Toolkit::for_each_with2(InputIterator first, InputIterator last, Function f, 
		  void* p1, void* p2)
{
  for ( ; first != last; ++first)
    f(*first, p1, p2);
  return f;
}


inline unsigned long
Toolkit::HashCStr(const unsigned char *name) 
{
	register unsigned long h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		if ( (g = (h & 0xf0000000)) ) h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

inline PConfig *GkConfig()
{
	return InstanceOf<Toolkit>()->Config();
}

inline PConfig *GkConfig(const char *section)
{
	return InstanceOf<Toolkit>()->Config(section);
}

#endif
