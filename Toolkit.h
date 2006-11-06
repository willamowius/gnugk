//////////////////////////////////////////////////////////////////
//
// Toolkit base class for the GnuGK
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
// 	991227  initial version (Torsten Will, mediaWays)
//
//////////////////////////////////////////////////////////////////

#ifndef TOOLKIT_H
#define TOOLKIT_H "@(#) $Id$"

#include <vector>
#include "singleton.h"

class H225_AliasAddress;
class H225_ArrayOf_AliasAddress;
class H225_H221NonStandard;
class H225_Setup_UUIE;
class SignalingMsg;
template <class> class H225SignalingMsg;
typedef H225SignalingMsg<H225_Setup_UUIE> SetupMsg;
struct SetupAuthData;

/// Hold an address of a single host or a whole network
struct NetworkAddress {
	/// Build an "any" address 
	NetworkAddress();
	/// Build a single host address
	NetworkAddress(
		const PIPSocket::Address &addr
		);
	/// Build an address of the specified network
	NetworkAddress(
		const PIPSocket::Address &addr,
		const PIPSocket::Address &nm
		);
	/// Build an address from the string
	NetworkAddress(
		const PString &str /// an address in a form A.B.C.D, A.B.C.D/24 or A.B.C.D/255.255.255.0
		);

	/// @return	Length of the network mask (number of significant bits)
	unsigned GetNetmaskLen() const;

	/** Compare two network addresses and define their relative order.
	    Ordering is done accordingly to netmask length and then to IP bytes.
		
	    @return <0 if this address is lesser than #addr#, 0 if both are equal,
	            >0 if this address is greater than #addr#.
	*/
	int Compare(
		const NetworkAddress &addr
		) const;

	/// @return	A string representation of the address in the form A.B.C.D/netmasklen
	PString AsString() const;

	/// @return	True if this is a wildcard address
	bool IsAny() const;
		
	/// @return	True if the given address is equal to this address
	bool operator==(const PIPSocket::Address &addr) const;
	bool operator==(const NetworkAddress &addr) const;

	/// @return	True if the given address is contained within this network		
	bool operator>>(const PIPSocket::Address &addr) const;
	bool operator>>(const NetworkAddress &addr) const;
	/// @return	True if the given network contains this network		
	bool operator<<(const NetworkAddress &addr) const;

	bool operator<(const NetworkAddress &addr) const;
	bool operator<=(const NetworkAddress &addr) const;
	bool operator>(const NetworkAddress &addr) const;
	bool operator>=(const NetworkAddress &addr) const;
	
	PIPSocket::Address m_address; /// host/network address
	PIPSocket::Address m_netmask; /// netmask for the #m_address#
};

/// @return	True if the given address equals to this address
bool operator==(const PIPSocket::Address &addr, const NetworkAddress &net);
/// @return	True if the given address is contained withing this network
bool operator<<(const PIPSocket::Address &addr, const NetworkAddress &net);

class GkTimerManager;
class CLIRewrite;
class Toolkit : public Singleton<Toolkit>
{
 public:
	// con- and destructing
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
		RouteTable() : rtable_begin(0), DynExtIP(false), ExtIP("") { /* initialize later */ }
		virtual ~RouteTable() { ClearTable(); }
		Address GetLocalAddress() const { return defAddr; };
		Address GetLocalAddress(const Address &) const;

		void InitTable();
		void ClearTable();
		bool IsEmpty() const { return rtable_begin == 0; }

		std::vector<NetworkAddress> GetInternalNetworks() { return m_internalnetworks; }

	    virtual bool IsMasquerade(PIPSocket::Address &) { return false; }
	protected:
		class RouteEntry : public PIPSocket::RouteEntry {
		public:
#ifndef _WIN32
			PCLASSINFO( RouteEntry, PIPSocket::RouteEntry )
#endif
			RouteEntry(const PString &);
			RouteEntry(const PIPSocket::RouteEntry &, const InterfaceTable &);
			bool Compare(const Address *) const;
		};
		virtual bool CreateTable() { return CreateRouteTable(); }
		bool CreateRouteTable(const PString & extroute=PString());

		RouteEntry *rtable_begin, *rtable_end;
		Address defAddr;

		std::vector<NetworkAddress> m_internalnetworks;
    	bool DynExtIP;
		PString ExtIP;
	};

	class VirtualRouteTable : public RouteTable {
		// override from class  RouteTable
	public:
		virtual bool IsMasquerade(PIPSocket::Address &);
	protected:
		virtual bool CreateTable();
		
	};

	RouteTable *GetRouteTable(bool = false);

	class ProxyCriterion {
		typedef PIPSocket::Address Address;

	public:
		ProxyCriterion();
		~ProxyCriterion();

		bool Required(const Address &, const Address &) const;

		void LoadConfig(PConfig *);

	protected:
		bool IsInternal(const Address & ip) const;
	
	private:
		bool m_enable;
		std::vector<NetworkAddress> m_networks;
	};

	bool ProxyRequired(const PIPSocket::Address & ip1, const PIPSocket::Address & ip2) const
	{ return m_ProxyCriterion.Required(ip1, ip2); }

	// Since PStringToString is not thread-safe,
	// I write this small class to replace that
	class RewriteData {
	public:
		RewriteData(PConfig *, const PString &);
		~RewriteData();
		void AddSection(PConfig *config, const PString & section);
		PINDEX Size() const { return m_size; }
		const PString & Key(PINDEX i) const { return m_RewriteKey[i]; }
		const PString & Value(PINDEX i) const { return m_RewriteValue[i]; }

	private:
		PString *m_RewriteKey, *m_RewriteValue;
		PINDEX m_size;
	};

	class RewriteTool {
	public:
		RewriteTool() : m_Rewrite(0) {}
		~RewriteTool() { delete m_Rewrite; }
		void LoadConfig(PConfig *);
		bool RewritePString(PString &) const;

	private:
		PString m_RewriteFastmatch;
		char m_TrailingChar;
		RewriteData *m_Rewrite;
	};

	/// maybe modifies #alias#. returns true if it did
	bool RewriteE164(H225_AliasAddress & alias);
	bool RewriteE164(H225_ArrayOf_AliasAddress & aliases);

	bool RewritePString(PString & s) { return m_Rewrite.RewritePString(s); }

	// Class to allow correct use of STL inside PDictionary type
	class GWRewriteEntry : public PObject {
		PCLASSINFO(GWRewriteEntry, PObject);
		public:
			std::pair<std::vector<std::pair<PString,PString> >,std::vector<std::pair<PString,PString> > > m_entry_data;
	};


	// per GW RewriteTool
	class GWRewriteTool {
		public:

			GWRewriteTool() {
				m_GWRewrite.AllowDeleteObjects(false);
			}
			~GWRewriteTool();
			void LoadConfig(PConfig *);
			void PrintData();
			bool RewritePString(PString gw, bool direction, PString &data);

		private:
			PDictionary<PString, GWRewriteEntry> m_GWRewrite;

	};

	// Equivalent functions to RewriteE164 group
	bool GWRewriteE164(PString gw, bool direction, H225_AliasAddress &alias);
	bool GWRewriteE164(PString gw, bool direction, H225_ArrayOf_AliasAddress &aliases);
	bool GWRewritePString(PString gw, bool direction, PString &data) { return m_GWRewrite.RewritePString(gw,direction,data); }

	PString GetGKHome(std::vector<PIPSocket::Address> &) const;
	void SetGKHome(const PStringArray &);

	bool isBehindNAT(PIPSocket::Address &);
	std::vector<NetworkAddress> GetInternalNetworks();

	// accessors
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

	/* This method modifies the config from status port
	 * Warning: don't modify the config via status port and change config file simultaneously,
	 * or the config file may be messed up.
	 */
	void SetConfig(int act, const PString & sec, const PString & key = PString::Empty(), const PString & value = PString::Empty());

	PConfig* ReloadConfig();

	/// reads name of the running instance from config
	static const PString & GKName();

	/// returns an identification of the binary
	static const PString GKVersion();

	/** simplify PString regex matching.
	 * @param str String that should match the regex
	 * @param regexStr the string which is compiled to a regex and executed with #regex.Execute(str, pos)#
	 * @return TRUE if the regex matched and FALSE if not or any error case.
	 */
	static BOOL MatchRegex(const PString &str, const PString &regexStr);

	/** returns the #BOOL# that #str# represents.
	 * Case insensitive, "t...", "y...", "a...", "1" are #TRUE#, all other values are #FALSE#.
	 */
	static bool AsBool(const PString & str);
	
	/** Convert a string to a time interval. The string should be formatted like:
			"1d5h" (1 day and 5 hours) or "20s" (20 seconds) or "1h" (1 hour)
			or "2000" (2000 milliseconds) or ...
		General format is a sequence of number and unit specifier pairs.
		Recognized unit specifiers:
			y - years
			M - months
			w - weeks
			d - days
			h - hours
			m - minutes
			s - seconds
			"empty" - milliseconds

		@return
		true if the input string contained properly formatted time interval,
		false if no conversion has been made
	*/
	static bool AsTimeInterval(
		/// formatted time interval string
		const char* inputString,
		/// variable to store calculated time interval on success
		PTimeInterval& interval
		);

	static void GetNetworkFromString(const PString &, PIPSocket::Address &, PIPSocket::Address &);

	static PString CypherDecode(const PString &, const PString &, int);

	/** you may add more extension codes in descendant classes. This codes will not be transferred
	 * or something it will be the return code of some methods for handling switches easy. */
	enum {
		iecUnknown     = -1,  /// internal extension code for an unknown triple(cntry,ext,manuf)
		iecFailoverRAS  = 1,   /// i.e.c. for "This RQ is a failover RQ" and must not be answerd.
		iecUserbase    = 1000 /// first guaranteed unused 'iec' by GnuGK Toolkit.
	};
	/** t35 extension or definitions as field for H225_NonStandardIdentifier */
	enum {
		t35cOpenOrg = 255,       /// country code for the "Open Source Organisation" Country
		t35mOpenOrg = 4242,     /// manufacurers code for the "Open Source Organisation"
		t35eFailoverRAS = 255  /// Defined HERE!
	};
	/** If the triple #(country,extension,manufacturer)# represents an
	 * extension known to the GnuGK this method returns its 'internal extension code'
	 # #iecXXX' or #iecUnknow# otherwise.
	 *
	 * Overwriting methods should use a simlilar scheme and call
	 * <code>
	 * if(inherited::GnuGKExtension(country,extension,menufacturer) == iecUnknown) {
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

	int GetInternalExtensionCode(const H225_H221NonStandard& data) const;

	/** A c-string (#char*#) hash function that considers the
	 * whole string #name# ending with #\0#.
	 */
	inline static unsigned long HashCStr(const unsigned char *name) ;

	/** Generate a call id for accounting purposes, that is unique
		during subsequent GK start/stop events.

		@return
		A string with the unique id.
	*/
	PString GenerateAcctSessionId();

	/** @return
	    A path to a temp directory.
	*/
	PString GetTempDir() const;
	
	/** @return
	    A pointer to the GkTimerManager object that allows registration
	    of time scheduled events.
	*/
	GkTimerManager* GetTimerManager() const { return m_timerManager; }

	/** Convert the timestamp into a string according to the passed
	    format string or (if it is an empty string) to the default format string.
	    The format string conforms to strftime formatting rules or can be a one
	    of predefined constants: Cisco, ISO8601, RFC822, MySQL.
		
	    @return	Formatted timestamp string.
	*/
	PString AsString(
		const PTime& tm, /// timestamp to convert into a string
		const PString& formatStr = PString() /// format string to use
		);

	/** Read and decrypt a password from the config. As a decryption key
	    this function is using the given key name padded with bytes of value
	    specified by the 'KeyFilled' config variable, if it is found
	    in the given config section, or a global padding byte.
		
	    @return
	    A decrypted password or an empty string, if the given key is missing.
	*/	
	PString ReadPassword(
		const PString &cfgSection, /// config section to read
		const PString &cfgKey, /// config key to read an encrypted password from
		bool forceEncrypted = false /// decrypt even if no KeyFilled is present
		);

	/// Inbound rewrite for ANI/CLI
	void RewriteCLI(
		SetupMsg &msg /// Q.931 Setup message to be rewritten
		) const;
		
	/// Outbound rewrite for ANI/CLI
	void RewriteCLI(
		SetupMsg &msg, /// Q.931 Setup message to be rewritten
		SetupAuthData &authData, /// additional data
		const PIPSocket::Address &destAddr /// callee's IP
		) const;

	void SetRerouteCauses(
		unsigned char *causeMap
		);
		
protected:
	void CreateConfig();
	void ReloadSQLConfig();
	void LoadCauseMap(PConfig *cfg);
	
	PFilePath m_ConfigFilePath;
	PFilePath m_extConfigFilePath;
	PString   m_GKName;
	PString   m_ConfigDefaultSection;
	PConfig*  m_Config;
	bool	  m_ConfigDirty;

	RewriteTool m_Rewrite;
	GWRewriteTool m_GWRewrite; // GW Based RewriteTool

	RouteTable m_RouteTable;
	VirtualRouteTable m_VirtualRouteTable;
	ProxyCriterion m_ProxyCriterion;

	std::vector<PIPSocket::Address> m_GKHome;

	/// a counter incremented for each generated session id
	long m_acctSessionCounter;
	/// base part for session id, changed with every GK restart
	long m_acctSessionBase;
	/// mutex for atomic session id generation (prevents from duplicates)
	PMutex m_acctSessionMutex;

private:
	PFilePath m_tmpconfig;
	/// global manager for time-based events
	GkTimerManager* m_timerManager;
	/// a default timestamp format string
	PString m_timestampFormatStr;
	/// a padding byte used during config passwords decryption
	int m_encKeyPaddingByte;
	/// if true, all passwords in the config are encrypted
	bool m_encryptAllPasswords;
	/// set of ANI/CLI rewrite rules
	CLIRewrite *m_cliRewrite;
	/// bit flag failover triggers for 128 Q931 causes
	unsigned char m_causeMap[16];
};


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
	return Toolkit::Instance()->Config();
}

inline PConfig *GkConfig(const char *section)
{
	return Toolkit::Instance()->Config(section);
}

inline const PString & Toolkit::GKName()
{
	return Toolkit::Instance()->m_GKName;
}

#endif // TOOLKIT_H
