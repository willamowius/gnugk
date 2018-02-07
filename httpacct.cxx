/*
 * httpacct.cxx
 *
 * accounting module for GNU Gatekeeper that sends it's messages over HTTP
 *
 * Copyright (c) 2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#include "config.h"

#if defined(P_HTTP) || defined (HAS_LIBCURL)

#include "httpacct.h"
#include "Toolkit.h"
#include <ptclib/http.h>

#ifdef HAS_LIBCURL
#include <curl/curl.h>
#endif // HAS_LIBCURL


HttpAcct::HttpAcct(const char* moduleName, const char* cfgSecName)
    : GkAcctLogger(moduleName, cfgSecName)
{
	// it is very important to set what type of accounting events
	// are supported for each accounting module, otherwise the Log method
	// will no get called
	SetSupportedEvents(HttpAcctEvents);

	PConfig* cfg = GetConfig();
	const PString & cfgSec = GetConfigSectionName();
	m_timestampFormat = cfg->GetString(cfgSec, "TimestampFormat", "");
    m_method = GkConfig()->GetString(cfgSec, "Method", "POST");
	m_startURL = cfg->GetString(cfgSec, "StartURL", "");
	m_startBody = cfg->GetString(cfgSec, "StartBody", "");
	m_stopURL = cfg->GetString(cfgSec, "StopURL", "");
	m_stopBody = cfg->GetString(cfgSec, "StopBody", "");
	m_updateURL = cfg->GetString(cfgSec, "UpdateURL", "");
	m_updateBody = cfg->GetString(cfgSec, "UpdateBody", "");
	m_connectURL = cfg->GetString(cfgSec, "ConnectURL", "");
	m_connectBody = cfg->GetString(cfgSec, "ConnectBody", "");
	m_alertURL = cfg->GetString(cfgSec, "AlertURL", "");
	m_alertBody = cfg->GetString(cfgSec, "AlertBody", "");
	m_registerURL = cfg->GetString(cfgSec, "RegisterURL", "");
	m_registerBody = cfg->GetString(cfgSec, "RegisterBody", "");
	m_unregisterURL = cfg->GetString(cfgSec, "UnregisterURL", "");
	m_unregisterBody = cfg->GetString(cfgSec, "UnregisterBody", "");
	m_onURL = cfg->GetString(cfgSec, "OnURL", "");
	m_onBody = cfg->GetString(cfgSec, "OnBody", "");
	m_offURL = cfg->GetString(cfgSec, "OffURL", "");
	m_offBody = cfg->GetString(cfgSec, "OffBody", "");
	m_rejectURL = cfg->GetString(cfgSec, "RejectURL", "");
	m_rejectBody = cfg->GetString(cfgSec, "RejectBody", "");
}

HttpAcct::~HttpAcct()
{
}

GkAcctLogger::Status HttpAcct::Log(GkAcctLogger::AcctEvent evt, const callptr & call)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;

	if (!call && evt != AcctOn && evt != AcctOff) {
		PTRACE(1, "HttpAcct\t" << GetName() << " - missing call info for event " << evt);
		return Fail;
	}

	PString eventURL;
	PString eventBody;
	if (evt == AcctStart) {
		eventURL = m_startURL;
		eventBody = m_startBody;
	} else if (evt == AcctConnect) {
		eventURL = m_connectURL;
		eventBody = m_connectBody;
	} else if (evt == AcctUpdate) {
		eventURL = m_updateURL;
		eventBody = m_updateBody;
	} else if (evt == AcctStop) {
		eventURL = m_stopURL;
		eventBody = m_stopBody;
	} else if (evt == AcctAlert) {
		eventURL = m_alertURL;
		eventBody = m_alertBody;
	} else if (evt == AcctOn) {
		eventURL = m_onURL;
		eventBody = m_onBody;
	} else if (evt == AcctOff) {
		eventURL = m_offURL;
		eventBody = m_offBody;
	} else if (evt == AcctReject) {
		eventURL = m_rejectURL;
		eventBody = m_rejectBody;
	}

	if (eventURL.IsEmpty()) {
		PTRACE(1, "HttpAcct\t" << GetName() << "Error: No URL configured for event " << evt);
		return Fail;
	}

    std::map<PString, PString> params;
    SetupAcctParams(params, call, m_timestampFormat);
    PString url = ReplaceAcctParams(eventURL, params);
    url = Toolkit::Instance()->ReplaceGlobalParams(url);
    PString body = ReplaceAcctParams(eventBody, params);
    body = Toolkit::Instance()->ReplaceGlobalParams(body);

	return HttpLog(url, body);
}

GkAcctLogger::Status HttpAcct::Log(GkAcctLogger::AcctEvent evt, const endptr & ep)
{
	// a workaround to prevent processing end on "sufficient" module
	// if it is not interested in this event type
	if ((evt & GetEnabledEvents() & GetSupportedEvents()) == 0)
		return Next;

	if (!ep) {
		PTRACE(1, "HttpAcct\t" << GetName() << " - missing endpoint info for event " << evt);
		return Fail;
	}

	PString eventURL;
	PString eventBody;
	if (evt == AcctRegister) {
		eventURL = m_registerURL;
		eventBody = m_registerBody;
	} else if (evt == AcctUnregister) {
		eventURL = m_unregisterURL;
		eventBody = m_unregisterBody;
	}

	if (eventURL.IsEmpty()) {
		PTRACE(1, "HttpAcct\t" << GetName() << "Error: No URL configured for event " << evt);
		return Fail;
	}

    std::map<PString, PString> params;
    SetupAcctEndpointParams(params, ep, m_timestampFormat);
    PString url = ReplaceAcctParams(eventURL, params);
    url = Toolkit::Instance()->ReplaceGlobalParams(url);
    PString body = ReplaceAcctParams(eventBody, params);
    body = Toolkit::Instance()->ReplaceGlobalParams(body);

	return HttpLog(url, body);
}

// TODO: refactor (copied from gkauth.cxx)
#ifdef HAS_LIBCURL
// receives the document data
static size_t CurlWriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    *((PString*)userp) = PString((const char*)contents, size * nmemb);
    return size * nmemb;
}

// receives debug output
static int DebugToTrace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
  PTRACE (6, "CURL\t" << PString((const char *)data, size).Trim());
  return 0;
}
#endif // HAS_LIBCURL

GkAcctLogger::Status HttpAcct::HttpLog(PString url, PString body)
{
    url.Replace(" ", "%20", true);  // TODO: better URL escaping ?
    PString host = PURL(url).GetHostName();
    PString result; // we have to capture the response, but we ignore it for now

    // TODO: check CURL concurrency
#ifdef HAS_LIBCURL
    CURLcode curl_res = CURLE_FAILED_INIT;
    CURL * curl = curl_easy_init();
    if (curl) {
        if (m_method == "GET") {
            // nothing special to do
        } else if (m_method == "POST") {
            PStringArray parts = url.Tokenise("?");
            if (body.IsEmpty() && parts.GetSize() == 2) {
                url = parts[0];
                body = parts[1];
            }
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)body);
        } else {
            PTRACE(2, "HttpAcct\tUnsupported method " << m_method);
            return Fail;
        }
        curl_easy_setopt(curl, CURLOPT_URL, (const char *)url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
        if (PTrace::CanTrace(6)) {
            curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, DebugToTrace);
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
        }
        curl_res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    if (curl_res != CURLE_OK) {
        PTRACE(2, "HttpAcct\tCould not GET password from " << host << " : " << curl_easy_strerror(curl_res));
        return Fail;
    }
#else
    if (url.Left(5) == "https") {
        PTRACE(2, "HttpPasswordAuth\tPlease compile GnuGk with libcurl for https support");
        return Fail;
    }
    PHTTPClient http;
    if (m_method == "GET") {
        if (!http.GetTextDocument(url, result)) {
            PTRACE(2, "HttpPasswordAuth\tCould not GET password from " << host);
            return Fail;
        }
    } else if (m_method == "POST") {
        PStringArray parts = url.Tokenise("?");
        if (body.IsEmpty() && parts.GetSize() == 2) {
            url = parts[0];
            body = parts[1];
        }
        PMIMEInfo outMIME;
        outMIME.SetAt(PMIMEInfo::ContentTypeTag(), "text/plain");
        PMIMEInfo replyMIME;
        if (!http.PostData(url, outMIME, body, replyMIME, result)) {
            PTRACE(2, "HttpPasswordAuth\tCould not POST to " << host);
            return Fail;
        }
    } else {
        PTRACE(2, "HttpPasswordAuth\tUnsupported method " << m_method);
        return Fail;
    }
#endif // HAS_LIBCURL

    return Ok;
}


namespace {
	// append HTTP accounting logger to the global list of loggers
	GkAcctLoggerCreator<HttpAcct> HttpAcctCreator("HttpAcct");
}

#endif // defined(P_HTTP) || defined (HAS_LIBCURL)
