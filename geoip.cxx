//////////////////////////////////////////////////////////////////
//
// geoip.cxx
//
// GeoIP authentication policy for GNU Gatekeeper
//
// Copyright (c) 2015-2018, Jan Willamowius
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
#include "Toolkit.h"
#include "rasinfo.h"
#include "RasPDU.h"
#include "gkauth.h"

#ifdef HAS_GEOIP2
#include <maxminddb.h>
#else
extern "C" {
#include "GeoIP.h"
}
#endif

/// GeoIP authentication policy

class GeoIPAuth : public GkAuthenticator
{
public:
	enum SupportedRasChecks {
		/// bitmask of RAS checks implemented by this module
		GeoIPAuthRasChecks = RasInfo<H225_RegistrationRequest>::flag
			| RasInfo<H225_AdmissionRequest>::flag
			| RasInfo<H225_GatekeeperRequest>::flag
			| RasInfo<H225_UnregistrationRequest>::flag
			| RasInfo<H225_BandwidthRequest>::flag
			| RasInfo<H225_DisengageRequest>::flag
			| RasInfo<H225_LocationRequest>::flag
			| RasInfo<H225_InfoRequest>::flag
			| RasInfo<H225_ResourcesAvailableIndicate>::flag
	};
	enum SupportedMiscChecks {
		/// bitmask of Misc checks implemented by this module
        GeoIPAuthMiscChecks = e_Setup
            | e_SetupUnreg
            | e_Connect
            | e_CallProceeding
            | e_Alerting
            | e_Information
            | e_ReleaseComplete
            | e_Facility
            | e_Progress
            | e_Empty
            | e_Status
            | e_StatusEnquiry
            | e_SetupAck
            | e_Notify
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
	virtual int Check(RasPDU<H225_AdmissionRequest> & request, ARQAuthData & authData);
	virtual int Check(RasPDU<H225_GatekeeperRequest> & grqPdu, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_UnregistrationRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_BandwidthRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_DisengageRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_LocationRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_InfoRequest> & req, unsigned & rejectReason);
	virtual int Check(RasPDU<H225_ResourcesAvailableIndicate> & req, unsigned & rejectReason);

	virtual int Check(SetupMsg & setup, SetupAuthData & authData);
    virtual int Check(Q931 & msg, Q931AuthData & authData);

protected:
	/** run the check on the IP

		@return
		e_ok 	if authentication OK
		e_fail	if authentication failed
		e_next	go to next policy
	*/
	int doGeoCheck(PIPSocket::Address & ip);

private:
	GeoIPAuth();
	GeoIPAuth(const GeoIPAuth &);
	GeoIPAuth & operator=(const GeoIPAuth &);

protected:
#ifdef HAS_GEOIP2
    MMDB_s m_mmdb;
#else
    GeoIP * m_gi;
#endif
    PStringArray m_allowedCountries;
};

GeoIPAuth::GeoIPAuth(const char * name, unsigned supportedRasChecks, unsigned supportedMiscChecks)
	: GkAuthenticator(name, supportedRasChecks, supportedMiscChecks)
{
	PString database = GkConfig()->GetString("GeoIPAuth", "Database", "geoip.dat");
#ifdef HAS_GEOIP2
    int status = MMDB_open(database, MMDB_MODE_MMAP, &m_mmdb);
	if (status != MMDB_SUCCESS) {
		PTRACE(2, "GeoIPAuth\tCan't read database " << database << " (expecting GeoIP2 database)");
		SNMP_TRAP(4, SNMPError, General, "GeoIPAuth: Can't read database");
	}
#else
    m_gi = GeoIP_open(database, GEOIP_MEMORY_CACHE);
	if (!m_gi) {
		PTRACE(2, "GeoIPAuth\tCan't read database " << database << " (expecting legacy GeoIP database)");
		SNMP_TRAP(4, SNMPError, General, "GeoIPAuth: Can't read database");
	}
#endif
    m_allowedCountries = GkConfig()->GetString("GeoIPAuth", "AllowedCountries", "").Tokenise(", ", false);
}

GeoIPAuth::~GeoIPAuth()
{
#ifdef HAS_GEOIP2
    MMDB_close(&m_mmdb);
#else
    if (m_gi) {
        GeoIP_delete(m_gi);
    }
#endif
}

int GeoIPAuth::Check(RasPDU<H225_RegistrationRequest> & rrqPdu, RRQAuthData & authData)
{
	return doGeoCheck((rrqPdu.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(RasPDU<H225_AdmissionRequest> & request, ARQAuthData & authData)
{
	return doGeoCheck((request.operator->())->m_peerAddr);
}

int GeoIPAuth::Check(RasPDU<H225_GatekeeperRequest> & request, unsigned &)
{
	return doGeoCheck((request.operator->())->m_peerAddr);
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

int GeoIPAuth::Check(RasPDU<H225_ResourcesAvailableIndicate> & request, unsigned &)
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

int GeoIPAuth::Check(Q931 & msg, Q931AuthData & authData)
{
	return doGeoCheck(authData.m_peerAddr);
}

int GeoIPAuth::doGeoCheck(PIPSocket::Address & ip)
{
#ifdef HAS_GEOIP2
#else
    if (!m_gi)
        return e_fail;
#endif

    PString country = "unknown";
    if (ip.IsRFC1918()) {
        country = "PRIVATE";
        // TODO: add similar check for IPv6 ?
    } else {
#ifdef HAS_GEOIP2
        int gai_error, mmdb_error;
        MMDB_lookup_result_s result = MMDB_lookup_string(&m_mmdb, ip.AsString(), &gai_error, &mmdb_error);
        if (gai_error == 0) {
            if (mmdb_error == MMDB_SUCCESS) {
                MMDB_entry_data_s entry_data;
                int status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
                if (status == MMDB_SUCCESS) {
                    if (entry_data.has_data) {
                        country = PString(entry_data.utf8_string, entry_data.data_size);
                    }
                }
            }
        } else {
            PTRACE(3, "GeoIPAuth\tError " << MMDB_strerror(mmdb_error));
        }
#else
        country = GeoIP_country_code_by_addr(m_gi, ip.AsString());
#endif
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
