// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// Toolkit base class for the OpenGK
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// $Id$
//
// History:
//      991227  initial version (Torsten Will, mediaWays)
//      020202  adding digt analysis (Martin Fröhlich, mediaWays)
//      020327  adding Shared Password crypto (Martin Fröhlich, mediaWays)
//
//////////////////////////////////////////////////////////////////

#if !defined(TOOLKIT_H)
#define TOOLKIT_H "@(#) $Id$"

#include <ptlib.h>
#include <ptlib/sockets.h>
#include "h225.h"
#include "singleton.h"

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 )
#endif

#if !defined(GK_LINEBRK)
#  if defined(WIN32)
#    define GK_LINEBRK "\r\n"
#  else
#    define GK_LINEBRK "\n"
#  endif
#endif


///////////////////////// Shared Secret Cryptography
#if defined(MWBB1_TAG)
#  include <MWCryptBB1.h>	// MWCrypt routines coding
#endif // MWBB1_TAG
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access and want to use it?
#  include <openssl/evp.h> // variuos definitions
#  include <openssl/bio.h>	// BIO type
#endif // P_SSL

class PTPW_Codec : public PObject
{
	PCLASSINFO(PTPW_Codec, PObject);
public:
	typedef enum {C_NULL=0, 
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access and want to use it?
#  if !defined(NO_DES)
		      C_DES, C_DES_EDE, C_DES_EDE3, C_DESX, 
#  endif // NO_DES
#  if !defined(NO_RC4)
		      C_RC4, 
#  endif // NO_RC4
#  if !defined(NO_IDEA)
		      C_IDEA,
#  endif // NO_IDEA
#  if !defined(NO_RC2)
		      C_RC2,
#  endif // NO_RC2
#  if !defined(NO_BF)
		      C_BF, 
#  endif // NO_BF
#  if !defined(NO_CAST)
		      C_CAST, 
#  endif // NO_CAST
#  if !defined(NO_RC5)
		      C_RC5,
#  endif // NO_RC5
#endif // P_SSL
#if defined(MWBB1_TAG)
		      C_MWBB1,
#endif // MWBB1_TAG
		      C_count} codec_kind;
	typedef enum { CT_KEEP=-1, CT_DECODE=0, CT_ENCODE=1 } coding_style;

	PTPW_Codec(codec_kind, coding_style);
	virtual ~PTPW_Codec();
	/// do the crypto stuff
	virtual const PString * cipher(PString &str);
	// service functions
	static const PString & Info(PString & in);
	static const char * const GetId(codec_kind k);
	static codec_kind GetAlgo(const PString &str);
protected:
	static const char * const init_section_name;
	static const char * PTPW_Ids[C_count];	// keep in sync with codec_kind
	codec_kind algo;	// kind of algorithm to use
	coding_style style;	// encoding, decoding?
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access and want to use it?
	BIO * bio_stack;	// cipher stack
	EVP_CIPHER * type;	// the cipher type information
private:
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char salt[PKCS5_SALT_LEN];
#endif // P_SSL
};


///////////////////////// Digit Analysis according to E.164

/** International Public Telecommunication Number in constrained string
 * representation. This is declared and implemented according to the
 * PASN_*String classes of PW-Lib.
 */
class E164_IPTNString : public PASN_ConstrainedString
{
	PCLASSINFO(E164_IPTNString, PASN_ConstrainedString);
public:
	E164_IPTNString(const char * str = NULL);
	E164_IPTNString(unsigned tag, TagClass tagClass);
	E164_IPTNString & operator=(const char * str);
        E164_IPTNString & operator=(const PString & str);
	virtual PObject * Clone() const;
	virtual PString GetTypeAsString() const;
	/**Calculate a hash value for use in sets and dictionaries.
	 *
	 * Needed for fast access (Factor 3000).
	 *
	 * @return
	 * hash value for International Public Telecommunication
	 * Number.
	 */
	virtual PINDEX HashFunction() const;
};



/** A telecommunication number splitted in compliance with E.164 6.2 into
 * Country Code, National Destination Code/Identification code, (Global)
 * Subscriber Number, and also determining the kind of IPTN if possible.
 */
class E164_AnalysedNumber {
private:			// std helper
	E164_AnalysedNumber & assign(const E164_AnalysedNumber &an); // basic assigment
public:				// Constructor/Destructor
	E164_AnalysedNumber();	// default const
	E164_AnalysedNumber(const E164_AnalysedNumber & an); // copy const
	~E164_AnalysedNumber();	// destructor

	E164_AnalysedNumber(const char * str); // from char *
	E164_AnalysedNumber(const PString & pstr); // from PString
	E164_AnalysedNumber(const E164_IPTNString & istr); // from E164_IPTNString
public:				// operators
	E164_AnalysedNumber & operator=(const E164_AnalysedNumber & an);
	E164_AnalysedNumber & operator=(const char * str);
	E164_AnalysedNumber & operator=(const PString & str);
	E164_AnalysedNumber & operator=(const E164_IPTNString & istr);
	operator E164_IPTNString();
	operator PString();
	PString GetAsDigitString() const;
public:				// class based types
	enum IPTN_kind_type     // kinds of International Public
			        // Telecommunication Numbers
	{
		IPTN_unknown = 0, // expressional completeness
		IPTN_geographical_areas, // E.164 6.2.1
		IPTN_global_services, // E.164 6.2.2
		IPTN_networks	// E.164 6.2.3
	};
protected:			// Members
	E164_IPTNString CC;	// Country Code
	E164_IPTNString NDC_IC;	// National Destination Code/Identification Code
	E164_IPTNString GSN_SN;	// (Global) Subscriber Number
	IPTN_kind_type IPTN_kind; // kind of IPTN detected here
public:				// Access methods
	const E164_IPTNString & GetCC();
	const E164_IPTNString & GetNDC_IC();
	const E164_IPTNString & GetGSN_SN();
	IPTN_kind_type  GetIPTN_kind();
private:
	E164_AnalysedNumber & analyse(PString pstr);
	// matching all but dialable digits
	static const PRegularExpression CleaningRegex;
};


/** In this class the information needed for a Digit Analysis is stored in
 * different Dictionaries (hence the naming 'library'). It is initialized
 * at construction from various files whose names are taken from the
 * configuration file(s) and therefore has to be instantiated after the
 * toolkit. The descent from the Singleton template class makes it possible
 * to assure a unique instantiation and protects us from wasting memory.
 */
class DigitCodeLibrary : public Singleton<DigitCodeLibrary>
{
public: // con- and destructing
	explicit DigitCodeLibrary();
	virtual ~DigitCodeLibrary();
protected:
	/** This is a mapping type (i.e. integer function) between an IPTN
	 *  code (E.164 well defined subsequences of IPTNs) and some
	 *  descriptive string.
	 */
	PDICTIONARY(CodeDict, E164_IPTNString, PString);

	// defining the general *pointer* type of a split function
	typedef E164_IPTNString (*split_functor_type)(E164_IPTNString);
	class split_functor_class : public PObject
	{
		PCLASSINFO(split_functor_class, PObject);
	public:
		split_functor_class(split_functor_type x){ p = x; };
		split_functor_type p;
	};
	class NDCAnalyserMethod : public PObject
	{
		PCLASSINFO(NDCAnalyserMethod, PObject);
	public:
		// Unions not allowed here, hence, if split_functor is
		// NULL, then the CodeDict is to be queried
		split_functor_type split_functor;
		CodeDict NDCDict; // the national code dict
	};

	/** This is the Mapping type between the Country Codes and
	 * registered directories or Numbering Plan based splitting
	 * functions */
	PDICTIONARY(MetaCodeDict, E164_IPTNString, NDCAnalyserMethod);

	/** Providing a mapping between the National Destination Code functors and
	 * their string indizes
	 */
	PDICTIONARY(FunctorDict, PString, split_functor_class);

	/** Providing a mapping between Shared Network Codes and their
	 * identification dics */
	PDICTIONARY(SNCodeDict, E164_IPTNString, CodeDict);
private:
	/** This is a mapping (i.e. integer function) between the country
	 * codes and their geographical area, global service or network as
	 * set forth in 'List of ITU-T Recommendation E.164 Assigned Country
	 * Codes' a 'Complement to ITU-T Recommendation E.164'
	 */
	CodeDict CCDict;
	/** This is a mapping (i.e. integer function) between the country
	 * codes and dictionaries or functonal operators (functors) which
	 * contain or yield the National Destination Codes for a given
	 * country code
	 */
	MetaCodeDict NDCMDict;
	/** Dict of Shared Network Codes to the below */
	SNCodeDict SNDict;
	/** This is a mapping between the Network Identification Codes and
	 * the network operators an their networks identifiers as set forth
	 * in 'List of ITU-T Recommendation E.164 Assigned Country Codes' a
	 * 'Complement to ITU-T Recommendation E.164'
	 */
	CodeDict * NICDict;
	/** This is a mapping between the GMSS Network Identification Codes
	 * and the network operators an their networks identifiers as set
	 * forth in 'List of ITU-T Recommendation E.164 Assigned Country
	 * Codes' a 'Complement to ITU-T Recommendation E.164'
	 */
	CodeDict * GMSSNICDict;
	/** This is a mapping (i.e. integer function) between the string indices and
	 *  National Destination Code functors
	 */
	FunctorDict FDict;
public:
	/** Test of existence of given Country Code in Country Code Map
	 *
	 * @return
	 * existence of given Country Code in Country Code Map
	 */
	BOOL IsCC(const E164_IPTNString &cc) const;
	/** Country of given Country Code in Country Code Map
	 *
	 * @return
	 * Country of given Country Code in Country Code Map
	 */
	const PString & CountryOf(const E164_IPTNString &cc) const;

	/** Test of existence of given National Destination Code in
	 * National Destination Map
	 *
	 * @return
	 * existence of given National Destination Code in National
	 * Destination Code Map
	 */
	BOOL IsNDC(const E164_IPTNString &cc, const E164_IPTNString &ndc) const;
	/** National Destination of given National Destination Code in
	 * National Destination Code Map
	 *
	 * @return
	 * National Destination of given National Destination Code in
	 * National Destination Code Map
	 */
	const PString & NationalDestinationOf(const E164_IPTNString &cc,
					      const E164_IPTNString &ndc) const;

	/** Test of existence of given Network Identification Shared Code in
	 * Network Identification Map
	 *
	 * @return
	 * existence of given Network Identification Shared Code in Network
	 * Identification Map
	 */
	BOOL IsNISC(const E164_IPTNString &nic) const;
	/** Test of existence of given Network Identification Code in
	 * Network Identification Shared Code range, using Network
	 * Identification Map
	 *
	 * @return
	 * existence of given Network Identification Code in given Network
	 * Identification Shared Code
	 */
	BOOL IsNIC(const E164_IPTNString &nisc, const E164_IPTNString &nic) const;
	/** Network Identification Code in Network Identification Shared
	 * Code range, using Network Identification Map
	 *
	 * @return
	 * Network Identification Code in given Network Identification
	 * Shared Code
	 */
	const PString & NetworkIdentificationOf(const E164_IPTNString &nisc,
						const E164_IPTNString &nic) const;

private:
	/* very local helper */
	void InsertInCCDictAndNDCMDict(const E164_IPTNString &key,
				       PString * const value);

};

///////////////////////  The Toolkit

class Toolkit : public Singleton<Toolkit>
{
public: // con- and destructing
	explicit Toolkit();
	virtual ~Toolkit();

	/// returns #basic# for
	virtual const PString GetName() const { return "basic"; }

	// by cwhuang
	// The idea was got from OpenGatekeeper,
	// but entirely implemented from scratch. :)
	class RouteTable {
		typedef PIPSocket::Address Address;
		typedef PIPSocket::InterfaceTable InterfaceTable;

	public:
		RouteTable() : rtable_begin(0) { /* initialize later */ }
		~RouteTable() { ClearTable(); }
		Address GetLocalAddress() const { return defAddr; };
		Address GetLocalAddress(Address) const;

		void InitTable();
		void ClearTable();

	private:
		class RouteEntry : public PIPSocket::RouteEntry {
		public:
#ifndef WIN32
			PCLASSINFO( RouteEntry, PIPSocket::RouteEntry )
#endif
			RouteEntry() :  PIPSocket::RouteEntry(Address()) {}
			RouteEntry(const PIPSocket::RouteEntry &, const InterfaceTable &);
			bool Compare(Address) const;
		};

	        RouteEntry *rtable_begin, *rtable_end;
		Address defAddr;
	};

	RouteTable *GetRouteTable() { return &m_RouteTable; }

	class ProxyCriterion {
		typedef PIPSocket::Address Address;

	public:
		ProxyCriterion() : network(0) { /* initialize later */ }
		~ProxyCriterion() { ClearTable(); }

		bool IsInternal(Address ip) const;
		bool Required(Address, Address) const;

		void LoadConfig(PConfig *);
		void ClearTable();

	private:
		int size;
		Address *network, *netmask;
	};

	bool ProxyRequired(PIPSocket::Address ip1, PIPSocket::Address ip2) const
		{ return m_ProxyCriterion.Required(ip1, ip2); }

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

	RouteTable m_RouteTable;
	ProxyCriterion m_ProxyCriterion;

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

#if (!defined HAS_NEW_H323SETALIASADDRESS)
void H323SetAliasAddress(const PString & name, H225_AliasAddress & alias, int tag);
#endif
#endif // TOOLKIT_H
