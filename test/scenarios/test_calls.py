"""Basic calls through GnuGk: plain and H.460.18/.19, without authentication, with MD5 and with H.235.1 tokens."""

import time

import pytest

from harness import gnugk, pcap, topology
from harness.endpoint import Endpoint

CALL_DURATION = 5	# seconds the caller keeps the call up
Q931_NORMAL_CLEARING = "16"

# (caller host, caller uses H.460.18, callee host, callee uses H.460.18, extra gatekeeper config)
PLACEMENTS = {
    "plain": ("pub1", False, "pub2", False, {}),
    "plain-noproxy": ("pub1", False, "pub2", False, {"Proxy": {"Enable": "0"}}),
    "plain-gk-h46018": ("pub1", False, "pub2", False, gnugk.h46018_config()),
    "h46018-caller": ("priv1", True, "pub2", False, gnugk.h46018_config()),
    "h46018-callee": ("pub1", False, "priv2", True, gnugk.h46018_config()),
    "h46018-both": ("priv1", True, "priv2", True, gnugk.h46018_config()),
}

# noauth, MD5 tokens, H.235.1 tokens checked in RAS + Setup, H.235.1 checked in every message
AUTH = ["noauth", "md5", "h2351-setup", "h2351-all"]
# how the media channels are opened: fastStart in the Setup, or H.245 OpenLogicalChannel
# (H.460.18/.19 endpoints only use H.245, see call_params())
MEDIA = ["faststart", "h245"]


def make_call(start_gk, workdir, placement, auth, media, tunneling=True, callee_tunneling=None,
              duration=CALL_DURATION, h46019m=False, extra_config=None, trace=None):
    """callee_tunneling: if it differs from the caller's (default: the same), h46019m: the H.460.18
    endpoints also use H.460.19 multiplexing, extra_config: more GnuGk config, trace: GnuGk trace level"""
    caller_host, caller_h46018, callee_host, callee_h46018, gk_config = PLACEMENTS[placement]
    if callee_tunneling is None:
        callee_tunneling = tunneling
    users = {}
    config = [gk_config] + ([extra_config] if extra_config else [])
    caller_pw = callee_pw = None
    h2351 = auth.startswith("h2351")
    if auth != "noauth":
        caller_pw, callee_pw = "secretA", "secretB"
        users = {"caller": caller_pw, "callee": callee_pw}
        config.append({"md5": gnugk.md5_config, "h2351-setup": gnugk.h2351_setup_config,
                       "h2351-all": gnugk.h2351_all_config}[auth]())
    gk = start_gk(*config, users=users, trace=trace)
    if caller_h46018 or callee_h46018:
        gk.require("h46018")

    faststart = (media == "faststart")
    callee = Endpoint(workdir, callee_host, "callee", password=callee_pw, h46018=callee_h46018, faststart=faststart,
                      h2351=h2351, tunneling=callee_tunneling, h46019m=h46019m and callee_h46018)
    caller = Endpoint(workdir, caller_host, "caller", password=caller_pw, h46018=caller_h46018, faststart=faststart,
                      h2351=h2351, tunneling=tunneling, h46019m=h46019m and caller_h46018)
    callee.start(duration=duration + 25)
    try:
        assert gk.wait_registered("callee"), "callee didn't register"
        caller.start(call="callee", duration=duration)
        caller_result = caller.wait(timeout=duration + 60)
        callee_result = callee.wait(timeout=duration + 60)
    finally:
        caller.kill()
        callee.kill()
    return gk, caller_result, callee_result


def check_call(gk, caller, callee, duration=CALL_DURATION):
    assert caller["registered"], "caller didn't register"
    assert callee["registered"], "callee didn't register"
    assert caller["connected"], "call wasn't established (caller: %s)" % caller["endReason"]
    assert callee["connected"], "callee never saw the call connect"
    assert caller["cleared"] and callee["cleared"]
    assert caller["endReason"] == "EndedByLocalUser", caller["endReason"]
    assert callee["endReason"] == "EndedByRemoteUser", callee["endReason"]

    # media must flow both ways for the whole call
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpSent"] > 100, "%s sent only %d RTP packets" % (side["alias"], side["rtpSent"])
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"], \
            "%s received %d of %d RTP packets" % (side["alias"], side["rtpReceived"], other["rtpSent"])

    # the gatekeeper accounted for the call and cleaned up
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    assert int(cdrs[0]["duration"]) >= duration - 1, cdrs[0]
    assert cdrs[0]["cause"] == Q931_NORMAL_CLEARING, cdrs[0]
    assert gk.number_of_calls() == 0

    # both endpoints unregistered on exit (URQ accepted)
    assert caller["unregistered"] and callee["unregistered"]
    time.sleep(0.5)
    assert not ({"caller", "callee"} & gk.registrations())


# known GnuGk bugs: (placement, auth) -> reason; strict, so a fix shows up as an XPASS failure
KNOWN_BUGS = {
    ("h46018-callee", "h2351-all"): "with all Q.931 messages checked, GnuGk rejects the H.460.18 Facility "
        "the callee uses to open its signaling channel (no call yet, so no authenticator for it)",
    ("h46018-both", "h2351-all"): "with all Q.931 messages checked, GnuGk rejects the H.460.18 Facility "
        "the callee uses to open its signaling channel (no call yet, so no authenticator for it)",
}


def call_params():
    for placement, (_, caller_h46018, _, callee_h46018, _) in PLACEMENTS.items():
        for auth in AUTH:
            for media in MEDIA:
                # fastStart isn't tested with H.460.18/.19 endpoints
                if media == "faststart" and (caller_h46018 or callee_h46018):
                    continue
                reason = KNOWN_BUGS.get((placement, auth))
                marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
                yield pytest.param(placement, auth, media, marks=marks, id="%s-%s-%s" % (placement, auth, media))


@pytest.mark.parametrize("placement,auth,media", list(call_params()))
def test_call(start_gk, workdir, capture, placement, auth, media):
    gk, caller, callee = make_call(start_gk, workdir, placement, auth, media)
    check_call(gk, caller, callee)
    proxy_ports = pcap.ports_used(capture, topology.GK_IP, "UDP", 40000, 41999)
    if placement == "plain-noproxy":
        assert not proxy_ports, "media went through the RTP proxy"
    else:
        assert proxy_ports, "media didn't go through the RTP proxy"
