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

#if (_MSC_VER >= 1200)
#pragma warning( disable : 4786 ) // warning about too long debug symbol off
#pragma warning( disable : 4800 ) // warning about forcing value to bool
#endif

#include "Toolkit.h"
#include "h323util.h"
#include "ANSI.h"
#include "stl_supp.h"
#include "CountryCodeTables.h"
#include <h323pdu.h>
#include "GkProfile.h"

#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access and want to use it?
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#  include <openssl/rand.h>
#  include <openssl/buffer.h>
#endif // P_SSL

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
static const char vcHid[] = TOOLKIT_H;
#endif /* lint */


// simplified output
#if !defined(TK_DBG_LVL)
#  define TK_DBG_LVL 4
#endif
// NOTE: Do not use the Status-error function. (Not initialized yet)! This
// environment provides its own error handling:
#define DEBUGPRINT(stream) PTRACE(TK_DBG_LVL, "GK\t" << ANSI::DBG << stream << ANSI::OFF);
#define ERRORPRINT(strpar) PTRACE(0, "GK\t" << ANSI::BRED << PString(strpar) << ANSI::OFF);

static const PString empty("");	// a local empty PString
static const char * const emptystr = ""; // a local empty String
extern const char * const ProxySection;

// class Toolkit::RouteTable::RouteEntry
Toolkit::RouteTable::RouteEntry::RouteEntry(
	const PIPSocket::RouteEntry & re,
	const InterfaceTable & it
	) : PIPSocket::RouteEntry(re)
{
	PINDEX i = 0;
	for (i = 0; i < it.GetSize(); ++i) {
		Address ip = it[i].GetAddress();
		if (Compare(ip)) {
			destination = ip;
			return;
		}
	}
	for (i = 0; i < it.GetSize(); ++i)
		if (it[i].GetName() == interfaceName) {
			destination = it[i].GetAddress();
			return;

		}
}

inline bool Toolkit::RouteTable::RouteEntry::Compare(Address ip) const
{
	return ((ip & net_mask) == network);
}

// class Toolkit::RouteTable
void Toolkit::RouteTable::InitTable()
{
	// Workaround for OS doesn't support GetRouteTable
	PIPSocket::GetHostAddress(defAddr);

	ClearTable();
	InterfaceTable if_table;
	if (!PIPSocket::GetInterfaceTable(if_table)) {
		PTRACE(1, "Error: Can't get interface table");
		return;
	}
	PTRACE(4, "InterfaceTable:\n" << setfill('\n') << if_table << setfill(' '));
	PIPSocket::RouteTable r_table;
	if (!PIPSocket::GetRouteTable(r_table)) {
		PTRACE(1, "Error: Can't get route table");
		return;
	}

	int i = r_table.GetSize();
	rtable_end = rtable_begin = new RouteEntry[i];
	for (PINDEX r = 0; r < r_table.GetSize(); r++) {
		PIPSocket::RouteEntry & r_entry = r_table[r];
		if (r_entry.GetNetMask() != INADDR_ANY)
			// It's unusual to contruct an object twice,
			// However, since RouteEntry is just a simple object,
			// it won't hurt. :p
			::new (rtable_end++) RouteEntry(r_entry, if_table);
	}

	// Set default IP according to route table
	PIPSocket::Address defGW;
	PIPSocket::GetGatewayAddress(defGW);
	defAddr = GetLocalAddress(defGW);

#ifdef PTRACING
	for (RouteEntry *entry = rtable_begin; entry != rtable_end; ++entry)
		PTRACE(2, "Network=" << entry->GetNetwork() << '/' << entry->GetNetMask() <<
		       ", IP=" << entry->GetDestination());
	PTRACE(2, "Default IP=" << defAddr);
#endif
}

void Toolkit::RouteTable::ClearTable()
{
	if (rtable_begin) {
		delete [] rtable_begin;
		rtable_begin = 0;
	}
}

PIPSocket::Address Toolkit::RouteTable::GetLocalAddress(Address addr) const
{
	RouteEntry *entry = find_if(rtable_begin, rtable_end,
				    bind2nd(mem_fun_ref(&RouteEntry::Compare), addr));
	return (entry != rtable_end) ? entry->GetDestination() : defAddr;
}

// class Toolkit::ProxyCriterion
void Toolkit::ProxyCriterion::LoadConfig(PConfig *config)
{
	ClearTable();
	if (!AsBool(config->GetString(ProxySection, "Enable", "0"))) {
		PTRACE(2, "GK\tH.323 Proxy disabled");
		size = -1;
		return;
	}

	PTRACE(2, "GK\tH.323 Proxy enabled");

	PStringArray networks(config->GetString(ProxySection, "InternalNetwork", "").Tokenise(" ,;\t", FALSE));
	if ((size = networks.GetSize()) == 0) {
		// no internal networks specified, always use proxy
		return;
	}

	network = new Address[size * 2];
	netmask = network + size;
	for (int i = 0; i < size; ++i) {
		GetNetworkFromString(networks[i], network[i], netmask[i]);
		PTRACE(2, "GK\tInternal Network " << i << " = " <<
		       network[i] << '/' << netmask[i]);
	}
}

void Toolkit::ProxyCriterion::ClearTable()
{
	size = 0;
	delete [] network;
	network = 0;
}

bool Toolkit::ProxyCriterion::Required(Address ip1, Address ip2) const
{
	return (size >= 0) ? ((size == 0) || (IsInternal(ip1) != IsInternal(ip2))) : false;
}

bool Toolkit::ProxyCriterion::IsInternal(Address ip) const
{
	for (int i = 0; i < size; ++i)
		if ((ip & netmask[i]) == network[i])
			return true;
	return false;
}

// class Toolkit::RewriteTool

static const char *RewriteSection = "RasSvr::RewriteE164";

void Toolkit::RewriteTool::LoadConfig(PConfig *config)
{
	m_RewriteFastmatch = config->GetString(RewriteSection, "Fastmatch", "");
	m_RewriteRules = config->GetAllKeyValues(RewriteSection);
	m_TrailingChar = config->GetString("RasSvr::ARQFeatures", "RemoveTrailingChar", " ")[0];
}

const BOOL Toolkit::RewriteTool::PrefixAnalysis(PString & number, unsigned int & ton, unsigned int & plan,
						unsigned int si, const CallProfile & profile) const
{
	PString internationalNumber;
	if(profile.GetInac() == number.Left(profile.GetInac().GetLength())) {
		PTRACE(5, "International Call");
		// It's a number in dialedDigits format (international)
		internationalNumber = number.Right(number.GetLength()-profile.GetInac().GetLength());
		ton = Q931::InternationalType;
	} else if (profile.GetInac().Left(number.GetLength()) == number) {
		// The number is a prefix of the INAC. So we cannot decide what TON it is.
		ton=Q931::UnknownType;
		return FALSE;
	} else { // This is definitely not an international Call.
		// Let's see, if it's a national call.
		if (profile.GetNac() == number.Left(profile.GetNac().GetLength())) {
			// Ok, it's a National Call.
			PTRACE(5, "National Call");
			internationalNumber = profile.GetCC() + number.Right(number.GetLength()-profile.GetNac().GetLength());
			ton = Q931::InternationalType;
		} else if (profile.GetNac().Left(number.GetLength()) == number) {
			// The number is a prefix of the NAC. So we cannot decide what TON it is.
			ton=Q931::UnknownType;
			return FALSE;
		} else { // Not an international nor a national Call.
			// next is to determine wether it's a local call.
			PTRACE(5, "Neither National nor International Call");
			if (profile.GetLac() == number.Left(profile.GetLac().GetLength())) {
				PTRACE(5, "LAC");
				internationalNumber = profile.GetCC() + profile.GetNDC_IC() + number.Right(number.GetLength()-profile.GetLac().GetLength());
				ton=Q931::InternationalType;
			} else if (profile.GetLac().Left(number.GetLength()) == number) {
				// The number is a prefix of the LAC. So we cannot decide what TON it is.
				// I don't know if that may ever happen -- but we are well prepared for it :-)
				ton=Q931::UnknownType;
				return FALSE;
			} else {
				PTRACE(5, "No Prefix");
				// This MUST be a internal call.
				internationalNumber = profile.GetCC() + profile.GetNDC_IC() + profile.GetSubscriberNumber() + number;
				ton=Q931::InternationalType;
			}
		}
	}
	PTRACE(5, "Returning number: " << internationalNumber);
	number = internationalNumber; // This is for future replacement of number-types
	return TRUE;
}

const enum Q931::TypeOfNumberCodes Toolkit::RewriteTool::PrefixAnalysis(PString & number, const CallProfile & profile) const
{
	PString internationalNumber;
	Q931::TypeOfNumberCodes ton=Q931::UnknownType;
	if(profile.GetInac() == number.Left(profile.GetInac().GetLength())) {
		PTRACE(5, "International Call");
		// It's a number in dialedDigits format (international)
		internationalNumber = number.Right(number.GetLength()-profile.GetInac().GetLength());
		ton = Q931::InternationalType;
	} else if (profile.GetInac().Left(number.GetLength()) == number) {
		// The number is a prefix of the INAC. So we cannot decide what TON it is.
		ton=Q931::UnknownType;
	} else { // This is definitely not an international Call.
		// Let's see, if it's a national call.
		if (profile.GetNac() == number.Left(profile.GetNac().GetLength())) {
			// Ok, it's a National Call.
			PTRACE(5, "National Call");
			internationalNumber =number.Right(number.GetLength()-profile.GetNac().GetLength());
			ton = Q931::NationalType;
		} else if (profile.GetNac().Left(number.GetLength()) == number) {
			// The number is a prefix of the NAC. So we cannot decide what TON it is.
			ton=Q931::UnknownType;
		} else { // Not an international nor a national Call.
			// next is to determine wether it's a local call.
			PTRACE(5, "Neither National nor International Call");
			if (profile.GetLac() == number.Left(profile.GetLac().GetLength())) {
				PTRACE(5, "LAC");
				internationalNumber = number.Right(number.GetLength()-profile.GetLac().GetLength());
				ton=Q931::SubscriberType;
			} else if (profile.GetLac().Left(number.GetLength()) == number) {
				// The number is a prefix of the LAC. So we cannot decide what TON it is.
				// I don't know if that may ever happen -- but we are well prepared for it :-)
				ton=Q931::UnknownType;
			} else {
				PTRACE(5, "No Prefix");
				// This MUST be a internal call.
				internationalNumber = number;
				ton=Q931::AbbreviatedType;
			}
		}
	}
	number = internationalNumber; // This is for future replacement of number-types
	return ton;
}

bool Toolkit::RewriteTool::RewritePString(PString & s)
{
	bool changed = false;
	bool do_rewrite = false; // marker if a rewrite has to be done.

	// remove trailing character
	if (s[s.GetLength() - 1] == m_TrailingChar) {
		s = s.Left(s.GetLength() - 1);
		changed = true;
	}
	// startsWith?
	if (strncmp(s, m_RewriteFastmatch, m_RewriteFastmatch.GetLength()) != 0)
		return changed;

	PString t;
	for (PINDEX i = 0; i < m_RewriteRules.GetSize(); ++i) {
		PString key = m_RewriteRules.GetKeyAt(i);
		// try a prefix match through all keys
		if (s.Find(key) == 0) { // startWith
			// Rewrite to #t#. Append the suffix, too.
			// old:  01901234999
			//               999 Suffix
			//       0190        Fastmatch
			//       01901234    prefix, Config-Rule: 01901234=0521321
			// new:  0521321999
			t = m_RewriteRules.GetDataAt(i);
			// multiple targets possible
			if (!t) {
				const PStringArray ts = t.Tokenise(",:;&|\t ", FALSE);
				if (ts.GetSize() > 1) {
					PINDEX j = rand() % ts.GetSize();
                                       PTRACE(5, "GK\tRewritePString: randomly chosen [" << j << "] of " << t << "");
                                       t = ts[j];
                               }
			}

			// append the suffix
			t += s.Mid(key.GetLength());

			do_rewrite = true;
			break;
		}
	}

	//
	// Do the rewrite.
	// @param #t# will be written to #s#
	//
	if (do_rewrite) {
               PTRACE(2, "\tRewritePString: " << s << " to " << t << "");
               s = t;
               changed = true;
	}

	return changed;
}

Toolkit::Toolkit() : m_Config(0)
{
	srand(time(0));
}

Toolkit::~Toolkit()
{
	if (m_Config) {
		delete m_Config;
		PFile::Remove(m_tmpconfig);
	}
}

PConfig* Toolkit::Config()
{
	// Make sure the config would not be called before SetConfig
	PAssert(!m_ConfigDefaultSection, "Error: Call SetConfig() before Config()!");
	return (m_Config == NULL) ? ReloadConfig() : m_Config;
}

PConfig* Toolkit::Config(const char *section)
{
	Config()->SetDefaultSection(section);
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
	if (m_Config != NULL) {
		delete m_Config;
		PFile::Remove(m_tmpconfig);
	}

	// generate a unique name
	do {
#ifdef WIN32
		m_tmpconfig = m_ConfigFilePath + "-" + PString(PString::Unsigned, rand()%10000);
#else
		m_tmpconfig = "/tmp/gnugk.ini-" + PString(PString::Unsigned, rand()%10000);
#endif
		PTRACE(5, "Try name "<< m_tmpconfig);
	} while (PFile::Exists(m_tmpconfig));

#ifdef WIN32
	// Does WIN32 support symlink?
	if (PFile::Copy(m_ConfigFilePath, m_tmpconfig))
#else
		if (symlink(m_ConfigFilePath, m_tmpconfig)==0)
#endif
			m_Config = new PConfig(m_tmpconfig, m_ConfigDefaultSection);
		else // Oops! Create temporary config file failed, use the original one
			m_Config = new PConfig(m_ConfigFilePath, m_ConfigDefaultSection);

	m_RouteTable.InitTable();
	m_ProxyCriterion.LoadConfig(m_Config);
	m_Rewrite.LoadConfig(m_Config);
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



BOOL Toolkit::RewriteE164(H225_AliasAddress &alias)
{
	if (alias.GetTag() != H225_AliasAddress::e_dialedDigits)
		// there is nothing to do
		return TRUE;

	PString oldE164 = H323GetAliasAddressString(alias);
	PString newE164 = oldE164;

	BOOL changed = RewritePString(newE164);
	if (changed) {
		H323SetAliasAddress(newE164, alias);
		PTRACE(5, "\tRewriteE164: " << oldE164 << " to " << newE164);
	}

	return changed;
}



BOOL Toolkit::RewritePString(PString &s)
{
	return m_Rewrite.RewritePString(s);
}


const PString
Toolkit::GKName()
{
	return GkConfig()->GetString("Name", "OpenH323GK"); //use default section
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
		       "Gatekeeper(%s) Version(%s) Ext(pthreads=%d) Build(%s, %s) Sys(%s %s %s)" GK_LINEBRK,
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

///////////////////////// Digit Analysis according to E.164

/* CLASS  E164_IPTNString, see comment in header
 *
 * This structure is somewhat weird: the Constructor, Cast-operators and
 * cast operators do not match any scheme known to me, but I trust the
 * PW-Lib guys who had designed it.
 */

// the character set the string is constrained to.
static const char E164_IPTNStringSet[] =  " #*+.0123456789ABCDEF";
/* One 'rejection' class (0) and 16 hash classes
 * Special and 'rejectable' chars map to 0
 * digits map to (digit + 1)
 * letters map to 11-
 */
static const unsigned int HashTable[] = {
//       0   1   2   3   4   5   6   7   8   9
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  //   0 -   9
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  //  10 -  19
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  //  20 -  29
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  //  30 -  39  SPACE=32, #=35
	00,  0,  0,  0,  0,  0,  0,  0,  1,  2,  //  40 -  49  *=42, +=43, .=56 0=48
	03,  4,  5,  6,  7,  8,  9, 10,  0,  0,  //  50 -  59  9=57
	00,  0,  0,  0,  0, 11, 12, 13, 14, 15,  //  60 -  69  A=65
	16,  0,  0,  0,  0,  0,  0,  0,  0,  0,  //  70 -  79  F=70
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  //  80 -  89
	00,  0,  0,  0,  0,  0,  0, 11, 12, 13,  //  90 -  99  a=97  same as capitals
	14, 15, 16,  0,  0,  0,  0,  0,  0,  0,  // 100 - 109  f=102
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 110 - 119
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 120 - 129
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 130 - 139
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 140 - 149
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 150 - 159
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 160 - 169
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 170 - 179
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 180 - 189
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 190 - 199
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 200 - 209
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 210 - 219
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 220 - 229
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 230 - 239
	00,  0,  0,  0,  0,  0,  0,  0,  0,  0 // 240 -  249
};

E164_IPTNString::E164_IPTNString(const char * str) :
	PASN_ConstrainedString( E164_IPTNStringSet,
				sizeof( E164_IPTNStringSet)-1,
				UniversalPrintableString, // This is a HACK, but 'Printable' is a superset
				UniversalTagClass)
{
	PASN_ConstrainedString::SetValue(str);
}

E164_IPTNString::E164_IPTNString(unsigned tag, TagClass tagClass) :
	PASN_ConstrainedString( E164_IPTNStringSet,
				sizeof( E164_IPTNStringSet)-1,
				tag, tagClass)
{
	// this space left blank intentionally
}

E164_IPTNString &
E164_IPTNString::operator=(const char * str)
{
	PASN_ConstrainedString::SetValue(str);
	return *this;
}

E164_IPTNString &
E164_IPTNString::operator=(const PString & str)
{
	PASN_ConstrainedString::SetValue(str);
	return *this;
}

PObject *
E164_IPTNString::Clone() const
{
	PAssert(IsClass(E164_IPTNString::Class()), PInvalidCast);
	return new E164_IPTNString(*this);
}

PString
E164_IPTNString::GetTypeAsString() const
{
	return "E164_IPTNString";
}


PINDEX E164_IPTNString::HashFunction() const
{
#if 1
	const char * const theArray = (const char *)value;
	const PINDEX maxdigits = 20;
	PINDEX i = 0;
	unsigned int hash = 0;
	while ((i < maxdigits) && ('\0' != theArray[i])) {
		hash = (hash << 4) | (HashTable[theArray[i++]] + 1);
	}
	const PINDEX result = PABSINDEX(hash)%127;
#else
	const PINDEX result = value.HashFunction();
#endif
	//DEBUGPRINT(PString("E164_IPTNString::HashFunction ") << ANSI::RED << value
	//	   << ANSI::OFF<< " maps to " << ANSI::GRE << result << ANSI::OFF);
	return result;
}


/* CLASS E164_AnalysedNumber
 *
 * This class is designed by the following scheme:
 *
 * - besides the pure constructor a basic assigment function is handling
 *   all assigment task
 *
 * - Copy const. and assigment opartors use the basic assigment function
 *
 * - Cast operators handle the actual splitting
 */



// std helper
E164_AnalysedNumber &		// basic assigment
E164_AnalysedNumber::assign(const E164_AnalysedNumber &an)
{
	CC = an.CC;
	NDC_IC = an.NDC_IC;
	GSN_SN = an.GSN_SN;
	return *this;
}

// Constructor/Destructor

// default const
E164_AnalysedNumber::E164_AnalysedNumber()
	: CC(emptystr), NDC_IC(emptystr), GSN_SN(emptystr), IPTN_kind(IPTN_unknown)
{
	// this space left blank intentionally
}

// copy const
E164_AnalysedNumber::E164_AnalysedNumber(const E164_AnalysedNumber & an)
	: CC(emptystr), NDC_IC(emptystr), GSN_SN(emptystr), IPTN_kind(IPTN_unknown)
{
	assign(an);
}

// destructor
E164_AnalysedNumber::~E164_AnalysedNumber()
{
	// this space left blank intentionally
}

// cast constructor from char *
E164_AnalysedNumber::E164_AnalysedNumber(const char * str)
	: CC(emptystr), NDC_IC(emptystr), GSN_SN(emptystr), IPTN_kind(IPTN_unknown)
{
	assign(analyse(str));
}

// cast constructor from PString
E164_AnalysedNumber::E164_AnalysedNumber(const PString & pstr)
	: CC(emptystr), NDC_IC(emptystr), GSN_SN(emptystr), IPTN_kind(IPTN_unknown)
{
	assign(analyse(pstr));
}

// cast constructor from E164_IPTNString
E164_AnalysedNumber::E164_AnalysedNumber(const E164_IPTNString & istr)
	: CC(emptystr), NDC_IC(emptystr), GSN_SN(emptystr), IPTN_kind(IPTN_unknown)
{
	assign(analyse(istr.GetValue()));
}

// operators

// self assign operator
E164_AnalysedNumber &
E164_AnalysedNumber::operator=(const E164_AnalysedNumber & an)
{
	if(this == &an) return *this; // prevent identical copy
	assign(an);
	return *this;
}

// assign operator from char *
E164_AnalysedNumber &
E164_AnalysedNumber::operator=(const char * str)
{
	assign(str);
	return *this;
}

// assign operator from PString
E164_AnalysedNumber &
E164_AnalysedNumber::operator=(const PString & str)
{
	assign(analyse(str));
	return *this;
}

// assign operator from E164_IPTNString
E164_AnalysedNumber &
E164_AnalysedNumber::operator=(const E164_IPTNString & istr)
{
	assign(analyse(istr.GetValue()));
	return *this;
}

// cast operator
E164_AnalysedNumber::operator PString()
{
	PString A;
	if(0 < CC.GetValue().GetLength()) A += "+" + CC.GetValue();
	A += " " + NDC_IC.GetValue() + " " + GSN_SN.GetValue();
	return A;
}

// cast operator
E164_AnalysedNumber::operator E164_IPTNString()
{
	PString A;
	if(0 < CC.GetValue().GetLength()) A += "+" + CC.GetValue();
	A += " " + NDC_IC.GetValue() + " " + GSN_SN.GetValue();
	return E164_IPTNString(A);
}

// get as a sequence of digits
PString
E164_AnalysedNumber::GetAsDigitString() const
{
	return (CC.GetValue() + NDC_IC.GetValue() + GSN_SN.GetValue());
} // E164_AnalysedNumber::GetAsDigitString

// encapsuladed access method
const E164_IPTNString &
E164_AnalysedNumber::GetCC() const
{
	return CC;
}

// encapsuladed access method
const E164_IPTNString &
E164_AnalysedNumber::GetNDC_IC() const
{
	return NDC_IC;
}

// encapsuladed access method
const E164_IPTNString &
E164_AnalysedNumber::GetGSN_SN() const
{
	return GSN_SN;
}

// encapsuladed access method
E164_AnalysedNumber::IPTN_kind_type
E164_AnalysedNumber::GetIPTN_kind() const
{
	return IPTN_kind;
}

// matching all but dialable digits
const PRegularExpression
E164_AnalysedNumber::CleaningRegex("([^0-9A-F]+)",
				   PRegularExpression::IgnoreCase);
E164_AnalysedNumber &
E164_AnalysedNumber::analyse(PString pstr)
{
	IPTN_kind = IPTN_unknown; // default
	DigitCodeLibrary * DCL = InstanceOf<DigitCodeLibrary>();
	PString tst(pstr.ToUpper()); // string to be tested

	DEBUGPRINT(tst+" is to be tested");
	{ // cleaning the tst string
		// FIXME: this should be done properly with regular
		// expressions, but they do not behave as expected..
		tst.Replace("+", "", TRUE);
		tst.Replace(" ", "", TRUE);
		tst.Replace("-", "", TRUE);
		tst.Replace("(", "", TRUE);
		tst.Replace(")", "", TRUE);
		tst.Replace("/", "", TRUE);
		tst.Replace(".", "", TRUE);
#if 0
		PINDEX pos = 0;	// position of matching sub-string
		PINDEX len = 0;	// length of matching sub-string

#if 0		PString RE;
		cout << endl << endl << "REGEXP: ";
		cin >> RE;
		cout << endl << "REGEXP: " << RE << endl;
		PRegularExpression CleaningRegex2(RE);
#endif
		if(PRegularExpression::NoError != CleaningRegex2.GetErrorCode()) {
			ERRORPRINT(PString("Regular Expression error: ")
				   + CleaningRegex2.GetErrorText());
		}
		DEBUGPRINT(PString("Match returns ") << tst.FindRegEx(CleaningRegex2, pos, len) << " with pos=" << pos << " and len=" << len);
		// matching all but dialable digits
		while(P_MAX_INDEX != tst.FindRegEx(CleaningRegex, pos, len)) {
			DEBUGPRINT(tst << " is to be cleaned at " << pos << " for "
				   << len << " characters");
			tst.Delete(pos, len); // ... and remove it
		}
#endif
	} // tst string cleaned
	DEBUGPRINT(tst+" is the cleaned string");

	if(tst.IsEmpty()) {
		ERRORPRINT("could not analyse empty number");
		return *this;
	}

	PINDEX i = 1;		// index in tst
	// go for the Country Code
	while(tst.GetLength() >= i) {
		const E164_IPTNString numbers_to_test(tst.Left(i++));
		//DEBUGPRINT("CC: Going to test for " + numbers_to_test.GetValue())
		if(DCL->IsCC(numbers_to_test)) {
			CC = numbers_to_test; // Country Code found
			DEBUGPRINT(CC.GetValue() + " is Country Code for "
				   + DCL->CountryOf(CC));
			break;
		}
	}
	if(0 == CC.GetValue().GetLength()) {
		ERRORPRINT("could not analyse number, got no Country Code");
		IPTN_kind = IPTN_unknown;
		return *this;
	}

	tst = tst.Mid(i-1);	// strip Country Code
	DEBUGPRINT(tst << " is stripped number (with index " << i <<")");
	i = 1;			// reset index, NDC or NIC has min. length of one

	if(DCL->IsNISC(CC)) {
		IPTN_kind = IPTN_networks;
		DEBUGPRINT(pstr+" is IPTN for networks");
		// go for the Network Identification Code
		while(tst.GetLength() >= i) {
			const E164_IPTNString numbers_to_test(tst.Left(i++));
			//DEBUGPRINT("NIC: Going to test for " + PString(numbers_to_test))
			if(DCL->IsNIC(CC,numbers_to_test)) {
				NDC_IC = numbers_to_test; // NIC found
				break;
			}
		}
		if(0 == NDC_IC.GetValue().GetLength()) {
			ERRORPRINT("could not analyse number, got no "
				   "Network Identification Code");
			IPTN_kind = IPTN_unknown;
			return *this;
		}
		DEBUGPRINT(pstr+" is IPTN " + ANSI::CYA + DCL->NetworkIdentificationOf(CC,NDC_IC));
	} else {
		IPTN_kind = IPTN_geographical_areas;
		DEBUGPRINT(pstr+" is IPTN for geographical areas");
		// go for the National Destination Code
		while(tst.GetLength() >= i) {
			const E164_IPTNString numbers_to_test(tst.Left(i++));
			//DEBUGPRINT("NDC: Going to test for " +
			//	   numbers_to_test.GetValue())
			if(DCL->IsNDC(CC,numbers_to_test)) {
				NDC_IC = numbers_to_test; // National Destination Code found
				break;
			}
		}
		if(0 == NDC_IC.GetValue().GetLength()) {
			ERRORPRINT("could not analyse number, got no "
				   "National Destination Code");
			IPTN_kind = IPTN_unknown;
			return *this;
		}
		DEBUGPRINT(pstr + " is IPTN in " +
			   DCL->NationalDestinationOf(CC,NDC_IC));
	}

	GSN_SN=tst.Mid(i-1);	// the rest has to be the (Global) Subscriber Number
	DEBUGPRINT(GSN_SN.GetValue() << " is GSN_SN (with index " << i <<")");
	if(0 >= tst.GetLength()) {
		ERRORPRINT("Could not analyse number!");
		IPTN_kind = IPTN_unknown;
		return *this;
	}

	return *this;
}



/** these are the National Destination Code functors and the mapping to
 * their string indizes for closed numbering plans
 */
typedef struct FunctorDictInitializer {
	const char * key;
	const DigitCodeLibrary::split_functor_type value;
} FunctorDictInitializer;
namespace Functor {		// avoid name clashes
	// closed numbering plan: North Amrerican Numbering Plan
	static E164_IPTNString NANP(E164_IPTNString n)
	{
		return E164_IPTNString(n.GetValue().Mid(1,3));
	}
	// closed numbering plan: Australian Numbering Plan
	static E164_IPTNString ANP(E164_IPTNString n)
	{
		return E164_IPTNString(n.GetValue().Mid(1,1));
	}
	static const FunctorDictInitializer FunctorList[] = {
		{"NorthAmericanNumberingPlan",Functor::NANP},
		{"AustralianNumberingPlan",Functor::ANP},
		{NULL,NULL}
	};
}

/* very local helper */
void
DigitCodeLibrary::InsertInCCDictAndNDCMDict(const E164_IPTNString &key,
					    PString * const value)
{
	// inster into CCDict
//	DEBUGPRINT("InsertInCCDictAndNDCMDict" << "\t(3): " << key);
	if(CCDict.Contains(key)) {
		DEBUGPRINT("InsertInCCDictAndNDCMDict\t: " << ANSI::GRE << "key " << key
			   << " exists");
	} else {
		if(!CCDict.SetAt(key, value)) {
			ERRORPRINT("DigitCodeLibrary\t: "
				   "Could not add into Dictionary: <"
				   + key + ">-<" + *value + ">");
		}
	}

	NDCAnalyserMethod * NDCvalue = new NDCAnalyserMethod();
	NDCvalue->split_functor = Functor::NANP; // default

	// insert into NDCMDict
	//DEBUGPRINT("InsertInCCDictAndNDCMDict" << "\tinitNDCMD(3): " << key);
	if(NDCMDict.Contains(key)) {
		DEBUGPRINT("InsertInCCDictAndNDCMDict\t: " << ANSI::GRE
			   << "key " << key  << " already exists in NDCMDict");
	} else { // containment of key
		if(!NDCMDict.SetAt(key, NDCvalue)) {
			ERRORPRINT("DigitCodeLibrary\tNDCMD: "
				   "Could not add enrty into "
				   "National Destination Code "
				   "meta-dictionary for: "
				   + key);
		}

	} // containment of key
}


/** This is a mapping (i.e. integer function) between the country codes and
 * their geographical area, global service or network as set forth in 'List
 * of ITU-T Recommendation E.164 Assigned Country Codes' a 'Complement to
 * ITU-T Recommendation E.164'.  The definitions are provided globally in
 * the TEXT segment but may be overwritten by a file named
 * <DefaultCCFileName> if given in the proper section of the configuration
 * file.
 */
DigitCodeLibrary::DigitCodeLibrary():
	NICDict(new CodeDict), GMSSNICDict(new CodeDict)
{
	const char * const GeneralSection = "DigitAnalysis::General";
	const char * const CCFileNameKey = "CountryCodes";
	const char * const DefaultCCFileName = "cc.dat";
	const char * const FunctorSection = "DigitAnalysis::Functor";
	const char * const DefaultFunctor = "NorthAmericanNumberingPlan";
	const char * const CountryCodeFileDelimitingChar = ";";
	const char * const NatDestCodeFileDelimitingChar = ";";

	{ // functor dict setup
		using namespace Functor;
		DEBUGPRINT("DigitCodeLibrary::DigitCodeLibrary initialising functor "
			   "dictionary from constants");
		PINDEX here=0;
		while(!((NULL == FunctorList[here].key)
			|| (NULL == FunctorList[here].value))){
			const PString key(FunctorList[here].key);
			split_functor_class * const value = new split_functor_class(FunctorList[here].value);
			//DEBUGPRINT(GeneralSection << "\tFD(3): <" << key << ">=<"
			//	   << value << ">");
			if(FDict.Contains(key)) {
				DEBUGPRINT(GeneralSection << "\tFD: key "
					   << ANSI::GRE << key << " exists");
			} else {
				if(!FDict.SetAt(key, value)) {
					ERRORPRINT("DigitCodeLibrary\tFD: "
						   "Could not add into "
						   "functor dictionary: <"
						   + key + ">");
				}
			}
			here++;
		}
	} // functor dict setup
	DEBUGPRINT("DigitCodeLibrary::DigitCodeLibrary using section "
		   << GeneralSection);

	// initializing National Destination Code at same instance


	PString ccfilename = GkConfig()->GetString(GeneralSection,
						   CCFileNameKey,
						   DefaultCCFileName);
	PFilePath ccfilepath(ccfilename);
	if(PFile::Exists(ccfilepath)
	   && PFile::Access(ccfilepath, PFile::ReadOnly)) { // it's a file
		/* The file read in has to be in the format
		 * <Code><CountryCodeFileDelimitingChar><Indentifier>
		 * and its default name is <DefaultCCFileName>
		 */
		DEBUGPRINT(GeneralSection << "\tCountryCodes in " << ccfilepath);
		PFile CCfile(ccfilepath, PFile::ReadOnly);
		PString line;
		while(!(CCfile >> line).eof()) {
			PStringArray line_array =
				line.Tokenise(CountryCodeFileDelimitingChar, FALSE);
			//DEBUGPRINT(GeneralSection << "\t" << ccfilename << " (2): "
			//	   << line);
			const E164_IPTNString key(line_array[0]);
			PString * value = new PString(line_array[1]);
			InsertInCCDictAndNDCMDict(key, value);
			//DEBUGPRINT(GeneralSection << "\t(3): " << key);
		}
	} else {		// it's not a file
		if(!ccfilename.IsEmpty()) { // in case it looks like a file
			DEBUGPRINT(GeneralSection << "\tCCD: "
						   << ANSI::BRED
						   << ccfilename << ANSI::OFF << ANSI::RED
						   << " is an invalid file, using fallback"
						   << ANSI::OFF);
		}
		using namespace ITU_T_E164_CodeTables;
		DEBUGPRINT(GeneralSection << "\tCountryCodes taken from global constants");
		// Going to initialise from const initializer
		PINDEX here = 0;
		while(!((NULL == AssignedCountyCodes[here].key)
			|| (NULL == AssignedCountyCodes[here].value))) {
			const E164_IPTNString key(AssignedCountyCodes[here].key);
			PString * value = new PString(AssignedCountyCodes[here].value);
			//DEBUGPRINT(GeneralSection << "\t(3): <" << key << ">=<"
			//	   << *value << ">");
			InsertInCCDictAndNDCMDict(key, value);
			here++;
		}
	}
	DEBUGPRINT(GeneralSection << "\tCountry Codes read!");
	{
		using namespace ITU_T_E164_CodeTables;
		// Going to initialise from const initializer
		PINDEX here = 0;
		while(!((NULL == AssignedNetworkIdentificationCode[here].key)
			|| (NULL == AssignedNetworkIdentificationCode[here].value))) {
			const E164_IPTNString key(AssignedNetworkIdentificationCode[here].key);
			PString * value =
				new PString(AssignedNetworkIdentificationCode[here].value);
			//DEBUGPRINT(GeneralSection << "\t(3): <" << key << ">=<"
			//	   << *value << ">");
			if(NICDict->Contains(key)) {
				DEBUGPRINT(GeneralSection << "\t: key "
					   << ANSI::GRE << key << " exists");
			} else {
				if(!NICDict->SetAt(key, value)) {
					ERRORPRINT("DigitCodeLibrary\t: "
						   "Could not add into Dictionary: <"
						   + key + ">=<" + *value + ">");
				}
			}
			here++;
		}
	}
	DEBUGPRINT(GeneralSection << "\tNetwork Identification Codes read!");
	{
		using namespace ITU_T_E164_CodeTables;
		// Going to initialise from const initializer
		PINDEX here = 0;
		while(!((NULL == AssignedGMSSNetworkIdentificationCode[here].key)
			|| (NULL == AssignedGMSSNetworkIdentificationCode[here].value))) {
			const E164_IPTNString key(AssignedGMSSNetworkIdentificationCode[here].key);
			PString * value = new PString(AssignedGMSSNetworkIdentificationCode[here].value);
			//DEBUGPRINT(GeneralSection << "\t(3): <" << key << ">=<"
			//	   << *value << ">");
			if(GMSSNICDict->Contains(key)) {
				DEBUGPRINT(GeneralSection << "\t: key "
					   << ANSI::GRE << key << " exists");
			} else {
				if(!GMSSNICDict->SetAt(key, value)) {
					ERRORPRINT("DigitCodeLibrary\t: "
						   "Could not add into Dictionary: <"
						   + key + ">=<" + *value + ">");
				}
			}
			here++;
		}
	}
	DEBUGPRINT(GeneralSection << "\tGMSSNetwork Identification Codes read!");

	/* now the final mapping for the Shared network codes is done */
	{
		if(!SNDict.SetAt("881", GMSSNICDict)) {
			ERRORPRINT("DigitCodeLibrary\t: "
				   "Could not add GMSS Network Identification Dict "
				   "into Dictionary");
		}
		if(!SNDict.SetAt("882", NICDict)) {
			ERRORPRINT("DigitCodeLibrary\t: "
				   "Could not add Network Identification Dict into "
				   "Dictionary");
		}
	}
	DEBUGPRINT(GeneralSection << "\tShared Network Identification Codes assigned!");

	/* Now we have to add a dictionary of dictionaries, which have to
	 * be filled by the existence of some keys in the configuration,
	 * otherwise the North American Numbering Plan will be used */

	/* first all the key-value pais in the Digit Analysis Functor
	 * Section are read in and if the value is a known functor the it
	 * is registered for that county code, or, if the value is a file,
	 * it is tried to read that as a code dict. If both fails, an error
	 * message is displayed and the north american numbering plan
	 * functor is registered as a fallback. The same functor is used
	 * for all country code for those no functor is supplied. */

	// get all keys in this section
	PStringList keys(GkConfig()->GetKeys(FunctorSection));

	PINDEX k_size = keys.GetSize();
	DEBUGPRINT(FunctorSection << "\tthere are " << k_size << " keys in this section");
	for(PINDEX i = 0; i < k_size; i++) { // for every key in section
		DEBUGPRINT(FunctorSection << "\tusing index " << i);
		PString &k = keys[i];
		PString v = GkConfig()->GetString(FunctorSection,
						  k, DefaultFunctor);
		E164_IPTNString cc(k);
		DEBUGPRINT(FunctorSection << "\tkey values: key<"
			   << k << "> = value<"
			   << v << ">");
		// not an intelligent, but a short name.
		NDCAnalyserMethod * a = new NDCAnalyserMethod();

		if(PFile::Exists(v) && PFile::Access(v, PFile::ReadOnly)) {
			DEBUGPRINT(FunctorSection << "\tGoing to read " << v);
			a->split_functor = NULL;
			// reading from file
			/* The file read in has to be in the format
			 * <Code><NatDestCodeFileDelimitingChar><Indentifier>
			 */
			DEBUGPRINT(FunctorSection << "\tNDCMD NatDestCodes in " << v);
			PFile NDCfile(v, PFile::ReadOnly);
			PString line;
			while(!(NDCfile >> line).eof()) {
				//DEBUGPRINT(FunctorSection << "\t" << v << " NDCMD(1)");
#if 1 // FIXME: Which method is faster?
				PINDEX sep = line.FindOneOf(NatDestCodeFileDelimitingChar);
				const E164_IPTNString key(line.Left(sep));
				PString * value = new PString(line.Mid(sep+1));
				//DEBUGPRINT(FunctorSection << "\tNDCMD" << ANSI::PIN
				//	   << key << " " << ANSI::CYA
				//	   << *value);
#else
				PStringArray line_array =
					line.Tokenise(NatDestCodeFileDelimitingChar,
						      FALSE);
				//DEBUGPRINT(FunctorSection << "\t" << v
				//	   << " NDCMD(2): " << line);
				const E164_IPTNString key(line_array[0]);
				PString * value = new PString(line_array[1]);
#endif
				//DEBUGPRINT(FunctorSection << "\tNDCMD(3): " << key);
				if(a->NDCDict.Contains(key)) {
					DEBUGPRINT(FunctorSection << "\tNDCMD: key "
						   << ANSI::GRE << key  << " exists");
				} else { // containment of key
					if(!a->NDCDict.SetAt(key, value)) {
						ERRORPRINT("DigitCodeLibrary\tNDCMD: "
							   "Could not add into Dictionary: "
							   + line);
					}
				} // containment of key
			} // while
		} else {	// file or functor
			DEBUGPRINT(FunctorSection << "\tNDCMD: Going to register " << v);
			a->split_functor = Functor::NANP; // default
			if(FDict.Contains(v)) {	// FDict[v] exists
				if(NULL != FDict[v].p) { // FDict[v] is valid
					a->split_functor = FDict[v].p; // via lookup
					DEBUGPRINT(FunctorSection << "\tNDCMD: "
						   << v << " registered by lookup");
				} else {
					DEBUGPRINT(FunctorSection << "\tNDCMD: "
						   << ANSI::BRED
						   << v << ANSI::OFF << ANSI::RED
						   << " is an invalid function!"
						   << ANSI::OFF);
					ERRORPRINT(PString(FunctorSection) + "\a\tNDCMD: "
						   + v + " is an invalid function!");
					continue;
				} // FDict[v] is valid
			} else {
				// neither file nor function
				DEBUGPRINT(FunctorSection << "\tNDCMD: " << ANSI::BRED
					   << v << ANSI::OFF << ANSI::RED
					   << " is neither file-map nor function!"
					   << ANSI::OFF);
				ERRORPRINT(PString(FunctorSection) + "\a\tNDCMD: " + v
					   + " is neither file-map nor function!");
				continue;
			} // FDict[v] exists
		} // file or functor

		DEBUGPRINT(FunctorSection << "\tNDCMD: Going to register "
			   "national dictionary");

		if(NDCMDict.Contains(cc)) { // containment of cc
			NDCMDict.RemoveAt(cc);
			DEBUGPRINT(FunctorSection << "\tNDCMD: " << ANSI::GRE
				   << "overwriting default object for key "
				   << cc << ANSI::BLU
				   << " in National Destination Code meta-dictionary");
		} // containment of cc
		if(!NDCMDict.SetAt(cc, a)) {
			ERRORPRINT("DigitCodeLibrary\tNDCMD: "
				   "Could not add enrty into "
				   "National Destination Code "
				   "meta-dictionary for: "
				   + cc);
		}

		DEBUGPRINT(FunctorSection << "\tNDCMD: National dictionary registered!");

	} // for all keys
	DEBUGPRINT(FunctorSection << "\tNational Destination Codes/Functors read!");
	//PAssert(FALSE,"Quit in PW");
}


DigitCodeLibrary::~DigitCodeLibrary()
{
	DEBUGPRINT("~DigitCodeLibrary()\tend of destructor");
}

/** Test of existence of given Country Code in Country Code Map
 *
 * @return
 * existence of given Country Code in Country Code Map
 */
BOOL
DigitCodeLibrary::IsCC(const E164_IPTNString &cc) const
{
	return CCDict.Contains(cc);
}

/** Country of given Country Code in Country Code Map
 *
 * @return
 * Country of given Country Code in Country Code Map
 */
const PString &
DigitCodeLibrary::CountryOf(const E164_IPTNString &cc) const
{
	return CCDict[cc];
}

/** Test of existence of given National Destination Code in
 * National Destination Map
 *
 * @return
 * existence of given National Destination Code in National
 * Destination Code Map
 */
BOOL
DigitCodeLibrary::IsNDC(const E164_IPTNString &cc, const E164_IPTNString &ndc) const
{
	if(!IsCC(cc)) {
		ERRORPRINT("IsNDC: could not check for " + ndc.GetValue()
			   + " in " + cc.GetValue() +  ", because " + cc.GetValue()
			   + " is not a registered Country Code!");
		return FALSE;
	}
	NDCAnalyserMethod &a = NDCMDict[cc]; // the methodology object
	if(NULL == a.split_functor) { // functor or direct lookup
		return (a.NDCDict).Contains(ndc);
	} else {
		E164_IPTNString area = (*(a.split_functor))(ndc);
		return (area == ndc);
	}
}

/** National Destination of given National Destination Code in
 * National Destination Code Map
 *
 * @return
 * National Destination of given National Destination Code in
 * National Destination Code Map
 */
const PString &
DigitCodeLibrary::NationalDestinationOf(const E164_IPTNString &cc, const E164_IPTNString &ndc) const
{
	NDCAnalyserMethod &a = NDCMDict[cc]; // the methodology object
	if(NULL == a.split_functor) { // functor or direct lookup
		return a.NDCDict[ndc]; // the string
	} else {
		// the dict uses a PObject here split_functor_class
		E164_IPTNString area = (*(a.split_functor))(ndc);
		if(area == ndc) {
			return empty;
		}
	}
	return empty;
}

/** Test of existence of given Network Identification Shared Code in
 * Network Identification Map
 *
 * @return
 * existence of given Network Identification Shared Code in Network
 * Identification Map
 */
BOOL
DigitCodeLibrary::IsNISC(const E164_IPTNString &nisc) const
{
	return SNDict.Contains(nisc);
}

/** Test of existence of given Network Identification Code in
 * Network Identification Shared Code range, using Network
 * Identification Map
 *
 * @return
 * existence of given Network Identification Code in given Network
 * Identification Shared Code
 */
BOOL
DigitCodeLibrary::IsNIC(const E164_IPTNString &nisc, const E164_IPTNString &nic) const
{
	if(SNDict.Contains(nisc)) {
		CodeDict & d=SNDict[nisc];
		return d.Contains(nic);
	} else {
		ERRORPRINT("unknown range " + nisc.GetValue());
		return FALSE;
	}
}


/** Network Identification Code in Network Identification Shared Code
 * range, using Network Identification Map
 *
 * @return
 * Network Identification Code in given Network Identification
 * Shared Code
 */
const PString &
DigitCodeLibrary::NetworkIdentificationOf(const E164_IPTNString &nisc,
					  const E164_IPTNString &nic) const
{
	if(SNDict.Contains(nisc)) {
		CodeDict & d=SNDict[nisc];
		return d[nic];
	} else {
		ERRORPRINT("unknown range " + nisc.GetValue());
		return empty;
	}
}


//////////////////////

// alternative to H323SetAliasAddress(const PString & name,
// H225_AliasAddress & alias) here the kind in qestion can be specified.
#if !defined(HAS_NEW_H323SETALIASADDRESS)
void H323SetAliasAddress(const PString & name, H225_AliasAddress & alias, int tag)
{
 	alias.SetTag(tag);
 	if(H225_AliasAddress::e_dialedDigits==tag) {
 		(PASN_IA5String &) alias = name;
 	} else {
 		(PASN_BMPString &) alias = name;
 	}
}
#endif // HAS_NEW_H323SETALIASADDRESS

//////////////////////////////

/* Common String based shared secret cryptography */


// keep in sync with codec_kind, has to be one bigger then live due to syntax rules
const char * PTPW_Codec::PTPW_Ids[PTPW_Codec::C_count] =
{"",
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access and want to use it?
#  if !defined(NO_DES)
 "{DES}", "{DES_EDE}", "{DES_EDE3}", "{DESX}",
#  endif // NO_DES
#  if !defined(NO_RC4)
 "{RC4}",
#  endif // NO_RC4
#  if !defined(NO_IDEA)
 "{IDEA}",
#  endif // NO_IDEA
#  if !defined(NO_RC2)
 "{RC2}",
#  endif // NO_RC2
#  if !defined(NO_BF)
 "{BF}",
#  endif // NO_BF
#  if !defined(NO_CAST)
 "{CAST}",
#  endif // NO_CAST
#  if !defined(NO_RC5)
 "{RC5}",
#  endif // NO_RC5
#endif // P_SSL
#if defined(MWBB1_TAG)
 MWBB1_TAG,
#endif // MWBB1_TAG
};

const char * const PTPW_Codec::init_section_name = "PlaintextPasswd::SharedSecret";
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access and want to use it?
static const PString & Base64_decode(PString & str);
static const PString & Base64_decode(PString & str)
{
	PString pstr (str + "\n");
	unsigned int slen = pstr.GetLength(); // input length
	char strbuf[slen+1];
	memmove(strbuf, (const char *)pstr, slen);
	BIO * const bio_k_mem_src = BIO_new_mem_buf(strbuf, slen);
	BIO * const bio_k_b64 = BIO_new(BIO_f_base64());
	BIO * const bio_k_buf = BIO_new(BIO_f_buffer());


	BIO * bio_b64_chain = bio_k_mem_src;
	bio_b64_chain = BIO_push(bio_k_b64, bio_b64_chain);
	bio_b64_chain = BIO_push(bio_k_buf, bio_b64_chain);

	// base64 is always equal or longer then binary representation
	const int bufsize = 10+slen;
	char buf[bufsize]; // this is initialized to zeros!
	int char_read = BIO_gets(bio_b64_chain, buf, bufsize-1);
	DEBUGPRINT(PString("Base64_decode: read ") << char_read << " characters");
	PAssert((-2 != char_read), PUnsupportedFeature);
	PAssert((bufsize>=char_read), "Memory overrun");
	buf[char_read] = '\0'; // produce a well formed c-string
	PString result(buf,char_read);
	DEBUGPRINT(PString("Base64_decode: [")
		   << ANSI::RED << str << ANSI::OFF << ANSI::DBG
		   << "] decoded to ["
		   << ANSI::GRE << result << ANSI::OFF << ANSI::DBG << "]");
	str = result;
	BIO_free_all(bio_b64_chain);
	return str;
}
#endif


PTPW_Codec::PTPW_Codec(codec_kind a, coding_style st):
	algo(a), style(st)
{
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access and want to use it?
	DEBUGPRINT("PTPW_Codec: (Open)SSL Library considered for " << PTPW_Ids[algo]);

	EVP_CIPHER * type = EVP_enc_null();
	EVP_MD * md = EVP_md5(); // EVP_md_null();
	// initialize iv, key and salt content
	strncpy((char*)iv,"123456789ABCDEFGHIJKLMNOP",sizeof(iv));
	strncpy((char*)key,"123456789ABCDEFGHIJKLMNOP",sizeof(key));
	strncpy((char*)salt,"123456789ABCDEFGHIJKLMNOP",sizeof(salt));

	// get the environment data
	PString pw(GkConfig()->GetString(init_section_name, PTPW_Ids[algo], "cGFzc3dvcmQ="));	// base64("password") == "cGFzc3dvcmQ="

	Base64_decode(pw);
	DEBUGPRINT(PString("PTPW_Codec::PTPW_Codec: Read [")
		   << ANSI::BRED << pw << ANSI::OFF << ANSI::DBG
		   << "] as shared secret");

	switch(algo) {
#ifndef NO_DES
	case C_DES:
		type = EVP_des_cbc();
		break;
//	case C_DES_EDE:
//		type = EVP_des_ede_cbc();
//		break;
	case C_DES_EDE3:
		type = EVP_des_ede3_cbc();
		break;
	case C_DESX:
		type = EVP_desx_cbc();
		break;
#endif
#ifndef NO_RC4
	case C_RC4:
		type = EVP_rc4();
		break;
#endif
#ifndef NO_IDEA
	case C_IDEA:
		type = EVP_idea_cbc();
		break;
#endif
#ifndef NO_RC2
	case C_RC2:
		type = EVP_rc2_cbc();
		break;
#endif
#ifndef NO_BF
	case C_BF:
		type = EVP_bf_cbc();
		break;
#endif
#ifndef NO_CAST
	case C_CAST:
		type = EVP_cast5_cbc();
		break;
#endif
#ifndef NO_RC5
	case C_RC5:
		type = EVP_rc5_32_12_16_cbc();
		break;
#endif
	default:
		type = EVP_enc_null();
		break;
	}

	// Definig stack members
	BIO * bio_mem = BIO_new(BIO_s_mem()); // memory source
	BIO * bio_b64 = BIO_new(BIO_f_base64()); // base64 coding
	BIO_set_flags(bio_b64,BIO_FLAGS_BASE64_NO_NL); // all in one line
	BIO * bio_cipher = BIO_new(BIO_f_cipher()); // any cipher
	BIO * bio_buf = BIO_new(BIO_f_buffer()); // memory buffer (eazy IO)

	if(NULL != bio_cipher) { // getting key from password
		EVP_BytesToKey(type, // const EVP_CIPHER *;
			       md, // EVP_MD *;
			       ((0==strlen((char*)salt))?NULL:salt), // const unsigned char *;
			       (const unsigned char*)pw, // const unsigned char *;
			       pw.GetLength(), // int;
			       1, // int; degree of digestion: number of time the digest function should be recursively applied.
			       key, // unsigned char *;
			       iv); // unsigned char *;
#if defined(PTRACING) && 1
		DEBUGPRINT("PTPW_Codec: ------------ cipher properties in use ------");
		for (unsigned int i=0; i < PKCS5_SALT_LEN; i++)
			DEBUGPRINT(PString("PTPW_Codec: ").sprintf("salt: %02X",salt[i]));
		for (unsigned int i=0; i < EVP_MAX_KEY_LENGTH; i++)
			DEBUGPRINT(PString("PTPW_Codec: ").sprintf("key: %02X",key[i]));
		for(unsigned int i=0; i < EVP_MAX_IV_LENGTH; i++)
			DEBUGPRINT(PString("PTPW_Codec: ").sprintf("iv: %02X",iv[i]));
		DEBUGPRINT("PTPW_Codec: ------------ cipher properties in use ------ ");
#endif
		BIO_set_cipher(bio_cipher, type, key, iv, style);
	}

	// Builing stack (joining list)
	bio_stack = bio_mem;	// anchor
	bio_stack = BIO_push(bio_b64, bio_stack);
	bio_stack = BIO_push(bio_cipher, bio_stack);
	bio_stack = BIO_push(bio_buf, bio_stack);
#endif // P_SSL
#if defined(MWBB1_TAG)
	DEBUGPRINT("PTPW_Codec: MWCrypt Library considered for " << PTPW_Ids[algo]);
#endif // MWBB1_TAG
}

PTPW_Codec::~PTPW_Codec()
{
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access?
	BIO_flush(bio_stack);
	BIO_free_all(bio_stack);
#endif // P_SSL
#if defined(MWBB1_TAG)		// do we have mwcrypt access?
#endif // MWBB1_TAG
}

const PString &
PTPW_Codec::Info(PString & in)
{
	PString info("PTPW_Codec info: Knowing of ");
	info &= PString((unsigned int)C_count) & "codecs: ";
	DEBUGPRINT("PTPW_Codec::Info:  " << C_count << " entries found");
	DEBUGPRINT("PTPW_Codec::Info: adding NULL " << C_NULL);
	info &= "NULL";
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access?
#  ifndef NO_DES
	DEBUGPRINT("PTPW_Codec::Info: adding C_DES" << C_DES);
	info &= PTPW_Ids[C_DES];
	DEBUGPRINT("PTPW_Codec::Info: adding C_DES_EDE " << C_DES_EDE);
	info &= PTPW_Ids[C_DES_EDE];
	DEBUGPRINT("PTPW_Codec::Info: adding C_DES_EDE3 " << C_DES_EDE3);
	info &= PTPW_Ids[C_DES_EDE3];
	DEBUGPRINT("PTPW_Codec::Info: adding C_DESX " << C_DESX);
	info &= PTPW_Ids[C_DESX];
#  endif
#  ifndef NO_RC4
	DEBUGPRINT("PTPW_Codec::Info: adding C_RC4 " << C_RC4);
	info &= PTPW_Ids[C_RC4];
#  endif
#  ifndef NO_IDEA
	DEBUGPRINT("PTPW_Codec::Info: adding C_IDEA " << C_IDEA);
	info &= PTPW_Ids[C_IDEA];
#  endif
#  ifndef NO_RC2
	DEBUGPRINT("PTPW_Codec::Info: adding C_RC2 " << C_RC2);
	info &= PTPW_Ids[C_RC2];
#  endif
#  ifndef NO_BF
	DEBUGPRINT("PTPW_Codec::Info: adding C_BF " << C_BF);
	info &= PTPW_Ids[C_BF];
#  endif
#  ifndef NO_CAST
	DEBUGPRINT("PTPW_Codec::Info: adding C_CAST " << C_CAST);
	info &= PTPW_Ids[C_CAST];
#  endif
#  ifndef NO_RC5
	DEBUGPRINT("PTPW_Codec::Info: adding C_RC5 " << C_RC5);
	info &= PTPW_Ids[C_RC5];
#  endif
#endif // P_SSL
#if defined(MWBB1_TAG)
	DEBUGPRINT("PTPW_Codec::Info: adding C_MWBB1 " << C_MWBB1);
	info &= PTPW_Ids[C_MWBB1];
#endif // MWBB1_TAG
	in = PString(vcid) + PString(GK_LINEBRK) + PString(vcHid) + PString(GK_LINEBRK) + info;
	return in;
}

const PString *
PTPW_Codec::cipher(PString & str)
{
	PString * result = &str; // actually working on str
	switch (algo) {
#if (defined(P_SSL) && (0 != P_SSL) && defined(USE_SCHARED_SECRET_CRYPT)) // do we have openssl access?
#ifndef NO_DES
	case C_DES:
	case C_DES_EDE:
	case C_DES_EDE3:
	case C_DESX:
#endif
#ifndef NO_RC4
	case C_RC4:
#endif
#ifndef NO_IDEA
	case C_IDEA:
#endif
#ifndef NO_RC2
	case C_RC2:
#endif
#ifndef NO_BF
	case C_BF:
#endif
#ifndef NO_CAST
	case C_CAST:
#endif
#ifndef NO_RC5
	case C_RC5:
#endif
	{
		// preparing input
		PString pstr(str + '\n'); // openssl-lib's 'feature'
		// moving input to temporary c-array
		const int strl = pstr.GetLength(); // input length
		char inbuf[strl+1];
		memmove(inbuf, (const char *)pstr, strl); // from pstr
		inbuf[strl]='\0'; // assure well-formed c-string
		DEBUGPRINT(PString("PTPW_Codec::cipher: converted [") << pstr << "] to [" << inbuf << "]");
		int char_written = BIO_puts(bio_stack, inbuf);
		PAssert((-2 != char_written), PUnsupportedFeature);
		DEBUGPRINT(PString("PTPW_Codec::cipher: written ") << char_written << " characters [" << inbuf << "]");
		PAssert(-1 != char_written, "Error in writing to BIO chain");
		// preparing temporary c-array for output
		const int outbufsize = 10+(10*strl);
		unsigned char outbuf[outbufsize];
		int char_read = BIO_read(bio_stack, outbuf, outbufsize);
		PAssert((-2 != char_read), PUnsupportedFeature);
// 		while((0>=char_read) && BIO_should_retry(bio_stack)) {
// 			char_read = BIO_read(bio_stack, outbuf, outbufsize);
// 		}
		if((0>=char_read) && BIO_should_retry(bio_stack))
			char_read = BIO_read(bio_stack, outbuf, outbufsize); // seond try ;)
		DEBUGPRINT(PString("PTPW_Codec::cipher: read ") << char_read << " characters");
		PAssert(0>char_read,"Unable to read from BIO");
		PAssert((outbufsize>=char_read), "Memory overrun");
		// moving output from temporary to resulting PString object
		outbuf[char_read] = '\0'; // produce a well-formed c-string
		str = PString((const char *)outbuf, char_read); // to str
	}
	break;
#endif // do we have openssl access? P_SSL
#if defined(MWBB1_TAG)		// do we have mwcrypt access?
	case C_MWBB1:
	{
		const int strlen = str.GetLength(); // input length
		const unsigned int bufsize = 10+(10*strlen);
		char * strbuf = (char *)calloc(bufsize, sizeof(char));
		memmove(strbuf, (const char *)str, strlen);
		switch(style) {
		case CT_DECODE:
			str = PString((char *)DeCryptBB1(strbuf));
			break;
		case CT_ENCODE:
			str = PString((char *)CryptBB1(strbuf));
			break;
		default:
			ERRORPRINT("PTPW_Codec::cipher: invalid style");
			DEBUGPRINT("PTPW_Codec::cipher: invalid style");
			break;
		} // switch(style)
		free(strbuf);
	}
		break;
#endif // MWBB1_TAG
	default:
		break;
	} // switch(algo)
	return result;
}

const char * const
PTPW_Codec::GetId(codec_kind k)
{
	return PTPW_Codec::PTPW_Ids[k];
}

PTPW_Codec::codec_kind
PTPW_Codec::GetAlgo(const PString &str)
{
	codec_kind result = C_NULL;
	// tail to head, because the empty string is prefix of every string
	for(unsigned int k = ((unsigned int)C_count - 1);
	    k > (unsigned int)C_NULL+1;
	    k--) {
		DEBUGPRINT("PTPW_Codec::GetAlgo: testing against "
			   << GetId((codec_kind)k));
		if(0 == str.Find(GetId((codec_kind)k))) {
			result = (codec_kind)k;
			continue;
		}
	}
	return result;
}


// End of $Source$
