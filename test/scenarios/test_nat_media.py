"""NAT without H.460.18, H.460.17, fake RTP from a third host (RTP injection and RTP bleed), RTP inactivity,
H.235 half-call media encryption and running out of RTP proxy ports."""

import subprocess
import time

import pytest

from harness import pcap, topology
from harness.calls import run_call
from harness.endpoint import Endpoint
from harness.rtp import RtpSprayer, proxy_ports

GK = topology.GK_IP
NAT1 = topology.NAT_ROUTERS["nat1"][0]


def check_media(caller, callee, share=0.8):
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= share * other["rtpSent"] > 0, \
            "%s received %d of %d RTP packets" % (side["alias"], side["rtpReceived"], other["rtpSent"])


# ---- NAT without H.460.18

class PortChangingNat:
    """make the nat1 router map RTP to other source ports (like many real NATs), not keep the endpoint's ports"""
    RULE = ["POSTROUTING", "-o", "eth0", "-p", "udp", "--dport", "40000:41999", "-j", "MASQUERADE",
            "--to-ports", "50000-50999"]

    def __enter__(self):
        topology.in_ns("nat1", "iptables", "-t", "nat", "-I", *self.RULE)
        return self

    def __exit__(self, *exc):
        topology.in_ns("nat1", "iptables", "-t", "nat", "-D", *self.RULE, check=False)


# A NAT that "keeps ports" isn't tested: GnuGk's first packets to the NAT's IP and the signaled port often arrive
# before the caller's first RTP packet, the NAT router's conntrack then already has that tuple, and the caller's
# RTP gets another port anyway (a race the test can't control)
@pytest.mark.parametrize("nat,ignore_signaled,media_to_caller", [
    ("changes-ports", "0", False),
    ("changes-ports", "1", True),
], ids=["changes-ports", "changes-ports-IgnoreSignaledIPs"])
def test_nat_outbound_call(start_gk, workdir, capture, nat, ignore_signaled, media_to_caller):
    """a caller behind NAT (no H.460.18) calls a public endpoint, ProxyForNAT=1: GnuGk detects the NAT and proxies
    the call; it sends the caller's media to the NAT's IP and the signaled port, so with a NAT that changes the
    ports the media doesn't reach the caller (the manual's precondition for ProxyForNAT), unless
    IgnoreSignaledIPs=1 (GnuGk learns the address from the caller's RTP)"""
    gk = start_gk({"Proxy": {"ProxyForNAT": "1", "IgnoreSignaledIPs": ignore_signaled}})
    caller, callee = Endpoint(workdir, "priv1", "caller"), Endpoint(workdir, "pub2", "callee")
    with PortChangingNat():
        caller_result, callee_result = run_call(gk, caller, "callee", callee=callee, duration=4)
    assert caller_result["connected"] and callee_result["connected"], caller_result
    assert gk.trace_count("is NAT type") >= 1 and gk.trace_count("proxy enabled. (ProxyForNAT)") >= 1
    assert callee_result["rtpReceived"] >= 0.8 * caller_result["rtpSent"] > 0, (caller_result, callee_result)
    if media_to_caller:
        assert caller_result["rtpReceived"] >= 0.8 * callee_result["rtpSent"], caller_result
    else:
        assert caller_result["rtpReceived"] == 0, caller_result
    assert pcap.count(capture, src=NAT1, dst=GK, dport=lambda p: 40000 <= p <= 41999) > 100, "media wasn't proxied"


@pytest.mark.parametrize("caller_host", ["pub2", "priv1"], ids=["from-public", "from-same-nat"])
def test_nat_inbound_call_fails_cleanly(start_gk, workdir, caller_host):
    """without H.460.18 (or GnuGk's own NAT traversal) a NATed endpoint can't be called, not even from behind the
    same NAT: the caller is released within the signaling timeout and no call or registration is left over"""
    gk = start_gk({"Proxy": {"ProxyForNAT": "1"}})
    started = time.time()
    caller, callee = run_call(gk, Endpoint(workdir, caller_host, "caller"), "callee",
                              callee=Endpoint(workdir, "priv1", "callee"), duration=2, callee_duration=25, timeout=30)
    elapsed = time.time() - started
    assert caller["registered"] and callee["registered"]
    assert not caller["connected"] and caller["cleared"], caller
    assert not callee["callAttempted"], "the Setup reached the NATed callee: %s" % callee
    assert elapsed < 40, "the caller waited %d seconds" % elapsed
    assert gk.wait_no_calls()
    assert not ({"caller", "callee"} & gk.registrations())


# ---- H.460.17

@pytest.mark.parametrize("direction", ["from-nat", "to-nat"])
def test_h46017(start_gk, workdir, capture, direction):
    """EnableH46017=1: endpoints that register over a TCP connection to the signaling port (RAS tunneled in
    Facility messages) can call each other in both directions, also behind NAT, with media through the proxy;
    no RAS goes over UDP"""
    gk = start_gk({"RoutedMode": {"EnableH46017": "1", "EnableH46018": "1"}})
    gk.require("h46017")
    nated = Endpoint(workdir, "priv1", "nated", h46017=True, faststart=False)
    public = Endpoint(workdir, "pub2", "public", h46017=True, faststart=False)
    if direction == "from-nat":
        caller, callee = run_call(gk, nated, "public", callee=public, duration=4)
    else:
        caller, callee = run_call(gk, public, "nated", callee=nated, duration=4)
    assert caller["registered"] and callee["registered"], (caller, callee)
    assert caller["connected"] and callee["connected"], caller
    check_media(caller, callee)
    assert not pcap.count(capture, "UDP", dst=GK, dport=lambda p: p == 1719), "RAS over UDP"
    assert pcap.ports_used(capture, GK, "UDP", 40000, 41999), "media didn't go through the proxy"
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["cause"] == "16", cdrs
    assert gk.wait_no_calls()


# ---- fake RTP from a third host

RTP_BLEED_IGNORE_SIGNALED = ("with IgnoreSignaledIPs=1 and no RestrictRTPSources, the first packet on a proxy port "
                             "decides where the media goes: a third host that sprays the proxy ports gets the call's "
                             "media (RTP bleed) and the real endpoint gets none")


@pytest.mark.parametrize("config,injection_blocked", [
    ({}, False),
    ({"LegacyPortDetection": "1"}, False),
    ({"RestrictRTPSources": "IP"}, True),
    ({"IgnoreSignaledIPs": "1", "RestrictRTPSources": "IP"}, True),
    pytest.param({"IgnoreSignaledIPs": "1"}, False, marks=pytest.mark.xfail(strict=True, reason=RTP_BLEED_IGNORE_SIGNALED)),
], ids=["default", "LegacyPortDetection", "RestrictRTPSources", "IgnoreSignaledIPs-RestrictRTPSources",
        "IgnoreSignaledIPs"])
def test_rtp_from_third_host(start_gk, workdir, config, injection_blocked):
    """pub3 sends fake RTP to every open RTP proxy port during a call: GnuGk never sends the call's media to pub3 (RTP
    bleed) and the endpoints keep getting each other's media; with RestrictRTPSources=IP none of pub3's packets
    reach an endpoint (without it GnuGk forwards them, that is what the switch is for)"""
    gk = start_gk({"Proxy": config})
    sprayer = RtpSprayer("pub3").start()
    try:
        caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                                  callee=Endpoint(workdir, "pub2", "callee", answer_delay=1), duration=5)
    finally:
        sprayer.stop()
    assert caller["connected"] and callee["connected"], caller
    assert sprayer.ports and sprayer.sent > 300, "the sprayer found no proxy ports: %s" % sorted(sprayer.ports)
    assert sprayer.received == 0, "pub3 got %d packets of the call's media (RTP bleed)" % sprayer.received
    check_media(caller, callee)
    if injection_blocked:
        for side, other in ((caller, callee), (callee, caller)):
            assert side["rtpReceived"] <= other["rtpSent"] + 5, \
                "%s got %d packets, %d were sent: injected RTP got through" % (side["alias"], side["rtpReceived"],
                                                                              other["rtpSent"])


# ---- RTP inactivity

@pytest.mark.parametrize("check", ["1", "0"], ids=["check", "no-check"])
def test_rtp_inactivity(start_gk, workdir, check):
    """[Proxy] RTPInactivityCheck=1, RTPInactivityTimeout=5: the callee freezes (SIGSTOP, its TCP connection
    stays up and it sends no RTP), GnuGk ends the call at its next check (once a minute) and writes the CDR;
    without the check the call stays"""
    gk = start_gk({"Proxy": {"RTPInactivityCheck": check, "RTPInactivityTimeout": "5"}})
    callee = Endpoint(workdir, "pub2", "callee").start(duration=120)
    caller = Endpoint(workdir, "pub1", "caller")
    try:
        assert gk.wait_registered("callee")
        caller.start(call="callee", duration=90)
        time.sleep(3)
        assert gk.number_of_calls() == 1
        callee.pause()
        started = time.time()
        ended = gk.wait_no_calls(timeout=75)
        took = time.time() - started
        calls_left = gk.number_of_calls()
    finally:
        callee.resume()
        caller.kill()
        callee.kill()
    if check == "1":
        assert ended, "the call is still up 75 seconds after the media stopped"
        assert took >= 4, "the call ended after %.1f seconds, before the timeout" % took
        assert gk.trace_count("CallTable\tTerminating call because of RTP inactivity") == 1
        assert len(gk.cdrs()) == 1, gk.cdrs()
    else:
        assert calls_left == 1, "the call ended without the check"


# ---- H.235 half-call media encryption

HALF_CALL_PT = ("the encrypting endpoint (H323Plus) sends its media with cipher payload type 96, GnuGk expects the "
                "dynamicRTPPayloadType of the OLC (120), so it doesn't decrypt ('Unexpected cipher payload type 96 "
                "expecting 120'), forwards header-only packets to the plain side, and nothing to the encrypting side")


@pytest.mark.xfail(strict=True, reason=HALF_CALL_PT)
def test_h235_half_call_media(start_gk, workdir):
    """EnableH235HalfCallMedia=1: the caller offers H.235.6 media encryption, the callee can't: GnuGk encrypts
    and decrypts for the caller's leg, the caller reports encrypted channels both ways, the callee plain ones,
    media flows both ways without payload type errors"""
    gk = start_gk({"RoutedMode": {"EnableH235HalfCallMedia": "1"}})
    gk.require("h235media")
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", h235_media=True, faststart=False), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", faststart=False), duration=4)
    assert caller["connected"] and callee["connected"], caller
    assert "tx:AES128" in caller["encryption"] and "rx:AES128" in caller["encryption"], caller["encryption"]
    assert callee["encryption"] == "", callee["encryption"]
    assert gk.trace_count("Unexpected cipher payload type") == 0
    check_media(caller, callee)


def test_h235_media_end_to_end(start_gk, workdir):
    """both endpoints encrypt (no half-call media): GnuGk passes the encryption through, media flows"""
    gk = start_gk()
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", h235_media=True, faststart=False), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", h235_media=True, faststart=False), duration=3)
    assert caller["connected"] and callee["connected"], caller
    for side in (caller, callee):
        assert "tx:AES128" in side["encryption"] and "rx:AES128" in side["encryption"], side
    check_media(caller, callee)


def test_require_h235_half_call_media(start_gk, workdir):
    """RequireH235HalfCallMedia=1: a call where neither side encrypts is ended"""
    gk = start_gk({"RoutedMode": {"EnableH235HalfCallMedia": "1", "RequireH235HalfCallMedia": "1"}})
    gk.require("h235media")
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", faststart=False), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", faststart=False), duration=4,
                              callee_duration=15)
    assert not (caller["connected"] and caller["durationMs"] > 2000), "the unencrypted call went on: %s" % caller
    assert gk.wait_no_calls()


# ---- running out of RTP proxy ports

def test_rtp_port_exhaustion(start_gk, workdir, capture):
    """[Proxy] RTPPortRange=40000-40003 (two calls' worth of ports) and four calls at the same time: GnuGk stays up,
    every call connects and has media both ways (the calls that get no proxy ports have their media sent
    directly), and once the calls are over (and GnuGk has deleted them) the ports are free
    for the next proxied call"""
    gk = start_gk({"Proxy": {"RTPPortRange": "40000-40003"}})
    callees = [Endpoint(workdir, "pub2", "callee%d" % i).start(duration=100) for i in range(5)]
    callers = []
    try:
        for i in range(5):
            assert gk.wait_registered("callee%d" % i)
        for i in range(4):
            callers.append(Endpoint(workdir, "pub1", "caller%d" % i).start(call="callee%d" % i, duration=6))
            time.sleep(1)
        assert proxy_ports() == {40000, 40001, 40002, 40003}, proxy_ports()
        results = [caller.wait() for caller in callers]
        # GnuGk closes the sockets of a call some time after it ended
        deadline = time.time() + 60
        while proxy_ports() and time.time() < deadline:
            time.sleep(1)
        assert not proxy_ports(), "proxy ports still open a minute after the calls: %s" % proxy_ports()
        last = Endpoint(workdir, "pub1", "caller4").start(call="callee4", duration=2)
        time.sleep(1.5)
        reused = proxy_ports()
        last_result = last.wait()
    finally:
        for endpoint in callees + callers:
            endpoint.kill()
    for result in results + [last_result]:
        assert result["connected"], result
        assert result["rtpReceived"] >= 0.8 * result["rtpSent"] > 0, result
    assert gk.trace_count("out of RTP sockets") > 0
    assert reused & {40000, 40002}, "the last call didn't get the freed ports: %s" % reused
    assert len(gk.cdrs()) == 5 and gk.alive()
