//////////////////////////////////////////////////////////////////
//
// geoip.cxx
//
// GeoIP authentication policy for GNU Gatekeeper
//
// Copyright (c) 2015, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#include "config.h"

#ifdef HAS_GEOIP

#include "snmp.h"
#include "rasinfo.h"
#include "RasPDU.h"
#include "gkauth.h"

extern "C" {
#include "GeoIP.h"
}

/// GeoIP authentication policy

class GeoIPAuth : public GkAuthenticator
{
public:
	enum SupportedRasChecks {
		/// bitmask of RAS checks implemented by this module
		GeoIPAuthRasChecks = RasInfo<H225_RegistrationRequest>::flag
			| RasInfo<H225_UnregistrationRequest>::flag
			| RasInfo<H225_BandwidthRequest>::flag
			| RasInfo<H225_DisengageRequest>::flag
			| RasInfo<H225_LocationRequest>::flag
			| RasInfo<H225_InfoRequest>::flag
			| RasInfo<H225_AdmissionRequest>::flag,
		GeoIPAuthMiscChecks = e_Setup | e_SetupUnreg
	};

	GeoIPAuth(
		const char* name, /// a name for this module (a config section name)
		unsigned supportedRasChecks = GeoIPAuthRasChecks,
		unsigned supportedMiscChecks = GeoIPAuthMiscChecks
		);

	virtual ~GeoIPAuth();

	/** Authenticate/Authorize RAS or signaling message.
	    An override from GkAuthenticator.

	    @return
	    e_fail - authentication rejected the request
	    e_ok - authentication accepted the request
	    e_next - authentication is not supported for this request
	             or cannot be determined (SQL failure, no cryptoTokens, ...)
	*/
	virtual int Check(RasPDU<H225_RegistrationRequest> & request, RRQAuthData & authData);
	virtual int Check(RasPDU<H225_UnregistrationRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_BandwidthRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_DisengageRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_LocationRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_InfoRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_AdmissionRequest> & request, ARQAuthData & authData);
	virtual int Check(SetupMsg & setup, SetupAuthData & authData);

protected:
	/** run the check on the IP

		@return
		e_ok 	if authentication OK
		e_fail	if authentication failed
		e_next	go to next policy
	*/
	int doGeoCheck(PIPSocket::Address & ip) const;

private:
	GeoIPAuth();
	GeoIPAuth(const GeoIPAuth &);
	GeoIPAuth & operator=(const GeoIPAuth &);

protected:
    GeoIP * m_gi;
    PStringArray m_allowedCountries;
};

GeoIPAuth::GeoIPAuth(
	const char * name,
	unsigned supportedRasChecks,
	unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks)
{
	PString database = GkConfig()->GetString("GeoIPAuth", "Database", "geoip.dat");
    m_gi = GeoIP_open(database, GEOIP_MEMORY_CACHE);
	if (m_gi) {
		m_allowedCountries = GkConfig()->GetString("GeoIPAuth", "AllowedCountries", "").Tokenise(", ", false);
	} else {
		PTRACE(2, "GeoIPAuth\tCan't read database " << database);
		SNMP_TRAP(4, SNMPError, General, "GeoIPAuth: Can't read database");
	}
}

GeoIPAuth::~GeoIPAuth()
{
    if (m_gi) {
        GeoIP_delete(m_gi);
    }
}

int GeoIPAuth::Check(RasPDU<H225_RegistrationRequest> & rrqPdu, RRQAuthData & authData)
{
	return doGeoCheck((rrqPdu.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(RasPDU<H225_UnregistrationRequest> & request, unsigned &)
{
	return doGeoCheck((request.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(RasPDU<H225_BandwidthRequest> & request, unsigned &)
{
	return doGeoCheck((request.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(RasPDU<H225_DisengageRequest> & request, unsigned &)
{
	return doGeoCheck((request.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(RasPDU<H225_LocationRequest> & request, unsigned &)
{
	return doGeoCheck((request.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(RasPDU<H225_InfoRequest> & request, unsigned &)
{
	return doGeoCheck((request.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(RasPDU<H225_AdmissionRequest> & request, ARQAuthData & authData)
{
	return doGeoCheck((request.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(SetupMsg & setup, SetupAuthData & authData)
{
	PIPSocket::Address addr;
	WORD port = 0;
	setup.GetPeerAddr(addr, port);
	return doGeoCheck(addr);
}

int GeoIPAuth::doGeoCheck(PIPSocket::Address & ip) const
{
    PString country;
    if (ip.IsRFC1918()) {
        country = "PRIVATE";
    } else {
        country = GeoIP_country_code_by_addr(m_gi, ip.AsString());
    }
    PTRACE(5, "GeoIPAuth\t" << ip.AsString() << " => " << country);
    for (PINDEX i = 0; i < m_allowedCountries.GetSize(); i++) {
        if (country == m_allowedCountries[i]) {
            return e_ok;
        }
    }
    PTRACE(3, "GeoIPAuth\tReject by country: " << country);
	return e_fail;
}

namespace { // anonymous namespace
	GkAuthCreator<GeoIPAuth> GeoIPAuthCreator("GeoIPAuth");
} // end of anonymous namespace

#endif	// HAS_GEOIP
