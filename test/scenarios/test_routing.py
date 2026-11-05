"""Routing modes and routing policies."""

import time

import pytest

from harness import pcap, topology
from harness.calls import run_call
from harness.gnugk import StatusSession
from harness.endpoint import Endpoint

GK = topology.GK_IP


def check_call_ok(caller, callee):
    assert caller["registered"] and callee["registered"]
    assert caller["connected"] and callee["connected"], caller["endReason"]
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)


def test_direct_mode(start_gk, workdir, capture):
    """GKRouted=0: the gatekeeper only does RAS, signaling and media go directly between the endpoints"""
    gk = start_gk({"RoutedMode": {"GKRouted": "0", "H245Routed": "0"}, "Proxy": {"Enable": "0"}})
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"))
    check_call_ok(caller, callee)
    assert len(gk.ras_events("ACF")) == 2, "expected an ACF for caller and callee"
    assert not pcap.ports_used(capture, GK, "TCP", 1720, 1720), "call signaling went through the gatekeeper"
    assert not pcap.ports_used(capture, GK, "UDP", 40000, 41999), "media went through the gatekeeper"
    # accounting comes from the DRQs
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and int(cdrs[0]["duration"]) >= 2, cdrs
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("tunneling", [True, False], ids=["tunneled", "separate-h245"])
def test_signal_routed_h245_direct(start_gk, workdir, capture, tunneling):
    """GKRouted=1, H245Routed=0, no proxy: Q.931 goes through the gatekeeper, a separate H.245
    channel and the media go directly between the endpoints"""
    gk = start_gk({"RoutedMode": {"H245Routed": "0"}, "Proxy": {"Enable": "0"}})
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", faststart=False, tunneling=tunneling), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", faststart=False, tunneling=tunneling))
    check_call_ok(caller, callee)
    assert caller["h245Tunneling"] == tunneling
    assert pcap.ports_used(capture, GK, "TCP", 1720, 1720), "call signaling didn't go through the gatekeeper"
    assert not pcap.ports_used(capture, GK, "TCP", 31000, 31999), "H.245 went through the gatekeeper"
    assert not pcap.ports_used(capture, GK, "UDP", 40000, 41999), "media went through the gatekeeper"
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["cause"] == "16", cdrs
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("target,config", [
    ("{ip}", {}),
    # H323Plus sends alias@ip as URL alias without destCallSignalAddress, the dns policy resolves it
    ("callee@{ip}", {"RoutingPolicy": {"default": "explicit,internal,dns"}}),
], ids=["ip", "alias-at-ip"])
def test_explicit_ip_dialing(start_gk, workdir, target, config):
    """a registered endpoint calls an unregistered one by IP (explicit routing policy, or the dns policy
    for alias@ip)"""
    gk = start_gk(config)
    callee_ip = topology.HOST_IPS["pub2"]
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), target.format(ip=callee_ip),
                              callee=Endpoint(workdir, "pub2", "callee", no_gk=True, listen_port=1720))
    assert caller["registered"] and not callee["registered"]
    assert caller["connected"] and callee["connected"], caller["endReason"]
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["callee_ip"] == callee_ip, cdrs
    assert gk.number_of_calls() == 0


def test_registered_callee_dialed_by_ip(start_gk, workdir, capture):
    """a call to the IP of a registered endpoint goes to that endpoint like a call to its alias: the CDR
    has its endpoint ID and the media goes through the proxy"""
    gk = start_gk()
    callee_ip = topology.HOST_IPS["pub2"]
    # (H323Plus sends "ip:port" as an H.323-ID, so only the plain IP is dialed)
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), callee_ip,
                              callee=Endpoint(workdir, "pub2", "callee", listen_port=1720))
    check_call_ok(caller, callee)
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["cause"] == "16", cdrs
    assert cdrs[0]["callee_ip"] == callee_ip, cdrs[0]
    assert cdrs[0]["callee_epid"], "the call wasn't associated with the registered callee: %s" % cdrs[0]
    assert pcap.ports_used(capture, GK, "UDP", 40000, 41999), "media didn't go through the RTP proxy"
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("dialed", ["9123", "pstngw"], ids=["prefix", "alias"])
def test_permanent_gateway(start_gk, workdir, dialed):
    """[RasSrv::PermanentEndpoints]: a gateway that never registers, reached by prefix or by alias"""
    gw_ip = topology.HOST_IPS["pub2"]
    gw_ep = Endpoint(workdir, "pub2", "gw", no_gk=True)
    gk = start_gk({"RasSrv::PermanentEndpoints": {"%s:%d" % (gw_ip, gw_ep.listen_port): "pstngw;9"}})
    assert "pstngw" in gk.registrations(), "permanent endpoint missing"
    caller, gw = run_call(gk, Endpoint(workdir, "pub1", "caller"), dialed, callee=gw_ep)
    assert caller["connected"] and gw["connected"], caller["endReason"]
    for side, other in ((caller, gw), (gw, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["callee_ip"] == gw_ip, cdrs
    assert "pstngw" in gk.registrations(), "permanent endpoint must stay registered"


def gateways(gk, workdir, count, calls=1, duration=40):
    gws = [Endpoint(workdir, "pub2", "gw%d" % i, gateway=True).start(duration=duration, calls=calls)
           for i in range(count)]
    for i in range(count):
        assert gk.wait_registered("gw%d" % i)
    return gws


def test_gateway_prefix_routing(start_gk, workdir):
    """[RasSrv::GWPrefixes]: numbers with the gateway's prefix go to the gateway, others are rejected"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9"}})
    gw = gateways(gk, workdir, 1)[0]
    try:
        caller, _ = run_call(gk, Endpoint(workdir, "pub1", "caller"), "9123", duration=2)
        unknown, _ = run_call(gk, Endpoint(workdir, "pub1", "caller", name="caller-unknown"), "8123", duration=2)
        gw_result = gw.wait()
    finally:
        gw.kill()
    assert caller["connected"] and gw_result["connected"], caller
    assert gw_result["calledNumber"] == "9123", gw_result
    assert not unknown["connected"]
    assert [e for e in gk.ras_events("ARJ") if e[5] == "calledPartyNotRegistered"], gk.ras_events("ARJ")


@pytest.mark.parametrize("round_robin", ["1", "0"])
def test_gateway_round_robin(start_gk, workdir, round_robin):
    """two gateways with the same prefix: with RoundRobinGateways=1 (default) 4 calls are spread 2/2,
    with 0 they all go to the same gateway"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9", "gw1": "9"},
                   "RasSrv::ARQFeatures": {"RoundRobinGateways": round_robin}})
    gws = gateways(gk, workdir, 2, calls=4, duration=15)	# they wait for up to 4 calls, but end after 15 s
    try:
        caller = Endpoint(workdir, "pub1", "caller").start(call="9123", duration=1, calls=4)
        caller_result = caller.wait()
        results = [gw.wait() for gw in gws]
    finally:
        for gw in gws:
            gw.kill()
    assert caller_result["callsConnected"] == 4, caller_result["calls"]
    per_gateway = sorted(len([c for c in r["calls"] if c["connected"]]) for r in results)
    assert per_gateway == ([2, 2] if round_robin == "1" else [0, 4]), per_gateway


def test_rewrite_e164(start_gk, workdir):
    """[RasSrv::RewriteE164]: the dialed number is rewritten before routing (0049 -> 9)"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9"}, "RasSrv::RewriteE164": {"0049": "9"}})
    gw = gateways(gk, workdir, 1)[0]
    try:
        caller, _ = run_call(gk, Endpoint(workdir, "pub1", "caller"), "0049123", duration=2)
        gw_result = gw.wait()
    finally:
        gw.kill()
    assert caller["connected"] and gw_result["connected"], caller
    assert gw_result["calledNumber"] == "9123", gw_result


@pytest.mark.parametrize("reject,fails_over", [("denied", True), ("busy", False)], ids=["cause-21", "cause-17"])
def test_failover(start_gk, workdir, reject, fails_over):
    """ActivateFailover: the first gateway refuses with a cause from FailoverCauses (21) and the call goes
    to the second one; a cause outside the list (17, busy) is passed to the caller"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9:=1", "gw1": "9:=2"},
                   "RoutedMode": {"ActivateFailover": "1"}})
    first = Endpoint(workdir, "pub2", "gw0", gateway=True, reject=reject).start(duration=12)
    second = Endpoint(workdir, "pub2", "gw1", gateway=True).start(duration=12)
    try:
        assert gk.wait_registered("gw0") and gk.wait_registered("gw1")
        caller, _ = run_call(gk, Endpoint(workdir, "pub1", "caller"), "9123", duration=2)
        first_result, second_result = first.wait(), second.wait()
    finally:
        first.kill()
        second.kill()
    assert first_result["callAttempted"] and not first_result["connected"], first_result
    if fails_over:
        assert caller["connected"] and second_result["connected"], (caller, second_result)
        for side, other in ((caller, second_result), (second_result, caller)):
            assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)
    else:
        assert not caller["connected"] and caller["q931Cause"] == 17, caller
        assert not second_result["callAttempted"], "failover with a cause that isn't in FailoverCauses"
    time.sleep(0.5)
    assert gk.number_of_calls() == 0


def call_gateway(gk, workdir, dialed, caller_alias="caller,1001"):
    """call the gateway gw0 (prefix 9) with dialed, returns caller result, gateway result and the CDR"""
    gw = gateways(gk, workdir, 1)[0]
    try:
        caller, _ = run_call(gk, Endpoint(workdir, "pub1", caller_alias), dialed, duration=2)
        gw_result = gw.wait()
    finally:
        gw.kill()
    assert caller["connected"] and gw_result["connected"], (caller, gw_result)
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    return caller, gw_result, cdrs[0]


@pytest.mark.parametrize("rules,expected", [
    ("caller=in=123=9123", "9123456"),
    ("caller=in=123=9123;gw0=out=9=00", "00123456"),
], ids=["in", "in-and-out"])
def test_gw_rewrite_e164(start_gk, workdir, rules, expected):
    """[RasSrv::GWRewriteE164]: inbound rules for the calling endpoint, outbound rules for the gateway"""
    caller_rule, _, out_rule = rules.partition(";")
    config = {"RasSrv::GWPrefixes": {"gw0": "9"},
              "RasSrv::GWRewriteE164": {"caller": caller_rule.split("=", 1)[1]}}
    if out_rule:
        config["RasSrv::GWRewriteE164"]["gw0"] = out_rule.split("=", 1)[1]
    gk = start_gk(config)
    _, gw, cdr = call_gateway(gk, workdir, "123456")
    assert gw["calledNumber"] == expected, gw
    assert cdr["dialed_number"] == "123456", cdr


def test_rewrite_cli(start_gk, workdir):
    """[RewriteCLI]: inbound rule for the caller's IP replaces its number, seen by the gateway and in the CDR"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9"},
                   "RewriteCLI": {"in:%s" % topology.HOST_IPS["pub1"]: "cli:1001=4971100"}})
    _, gw, cdr = call_gateway(gk, workdir, "9123")
    assert gw["callingNumber"] == "4971100", gw
    assert cdr["calling_station"] == "4971100", cdr


@pytest.mark.parametrize("answer", ["route", "reject", "timeout"])
def test_virtual_queue(start_gk, workdir, answer):
    """[CTI::Agents]: a call to the virtual queue 'sales' raises a RouteRequest on the status port; the
    application routes it to the callee (RouteToAlias), rejects it (RouteReject) or doesn't answer
    (RequestTimeout)"""
    gk = start_gk({"CTI::Agents": {"VirtualQueueAliases": "sales", "RequestTimeout": "3"},
                   "RoutingPolicy": {"default": "explicit,vqueue,internal"}})
    session = StatusSession()
    callee = Endpoint(workdir, "pub2", "callee").start(duration=30)
    caller = Endpoint(workdir, "pub1", "caller")
    try:
        assert gk.wait_registered("callee")
        caller.start(call="sales", duration=3)
        session.read_until("RouteRequest|")
        request = ("RouteRequest|" + session.read_until(";")).rstrip(";").split("|")
        assert request[4] == "sales", request
        epid, crv = request[2], request[3]
        if answer == "route":
            session.send("RouteToAlias callee %s %s" % (epid, crv))
        elif answer == "reject":
            session.send("RouteReject %s %s" % (epid, crv))
        caller_result = caller.wait()
        callee.kill()
    finally:
        session.close()
        caller.kill()
        callee.kill()
    if answer == "route":
        assert caller_result["connected"], caller_result
        cdrs = gk.cdrs()
        assert len(cdrs) == 1 and cdrs[0]["callee_ip"] == topology.HOST_IPS["pub2"], cdrs
    else:
        assert not caller_result["connected"], caller_result
        assert gk.ras_events("ARJ"), "no ARJ"
