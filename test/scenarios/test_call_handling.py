"""Call handling beyond the basic call: rejected and failed calls, who hangs up, ..."""

import time

import pytest

from harness import pcap, topology
from harness.calls import run_call
from harness.endpoint import Endpoint
from scenarios.test_calls import check_call, make_call


def test_call_to_unknown_alias(start_gk, workdir):
    """the gatekeeper rejects the ARQ, no call and no CDR are left"""
    gk = start_gk()
    caller, _ = run_call(gk, Endpoint(workdir, "pub1", "caller"), "nobody")
    assert caller["registered"]
    assert not caller["connected"]
    assert caller["endReason"] == "EndedByNoUser", caller["endReason"]
    arj = gk.ras_events("ARJ")
    assert len(arj) == 1 and arj[0][5] == "calledPartyNotRegistered", arj
    assert gk.number_of_calls() == 0
    assert gk.cdrs() == []


@pytest.mark.parametrize("reject,cause", [("busy", 17), ("denied", 21)])
def test_callee_refuses_call(start_gk, workdir, reject, cause):
    """the callee's reason reaches the caller and the CDR, the call is cleaned up"""
    gk = start_gk()
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", reject=reject), callee_duration=10)
    assert caller["registered"] and callee["registered"]
    assert not caller["connected"] and not callee["connected"]
    assert caller["q931Cause"] == cause, caller
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    assert cdrs[0]["cause"] == str(cause), cdrs[0]
    assert cdrs[0]["duration"] == "0", cdrs[0]
    assert cdrs[0]["released_by"] == "2", "should be released by the callee: %s" % cdrs[0]
    assert gk.number_of_calls() == 0


def test_callee_hangs_up(start_gk, workdir):
    """the callee ends the call: the caller gets the ReleaseComplete, the CDR has the callee as release source"""
    gk = start_gk()
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", hangup_after=3), duration=20)
    assert caller["connected"] and callee["connected"]
    assert callee["endReason"] == "EndedByLocalUser", callee["endReason"]
    assert caller["endReason"] == "EndedByRemoteUser", caller["endReason"]
    assert caller["durationMs"] < 10000, "caller didn't see the hangup: %d ms" % caller["durationMs"]
    assert caller["rtpReceived"] > 100 and callee["rtpReceived"] > 100
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    assert cdrs[0]["released_by"] == "2", "should be released by the callee: %s" % cdrs[0]
    assert cdrs[0]["cause"] == "16", cdrs[0]
    assert 2 <= int(cdrs[0]["duration"]) <= 5, cdrs[0]
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("placement", ["plain", "plain-noproxy", "h46018-caller", "h46018-callee", "h46018-both"])
def test_separate_h245_channel(start_gk, workdir, placement):
    """H.245 tunneling off: GnuGk routes (and proxies) H.245 over its own TCP connection"""
    gk, caller, callee = make_call(start_gk, workdir, placement, "noauth", "h245", tunneling=False)
    assert not caller["h245Tunneling"] and not callee["h245Tunneling"], "H.245 was tunneled"
    check_call(gk, caller, callee)


@pytest.mark.parametrize("media", ["faststart", "h245"])
@pytest.mark.parametrize("tunneling_side", ["caller", "callee"])
def test_h245_tunneling_translation(start_gk, workdir, capture, tunneling_side, media):
    """[RoutedMode] H245TunnelingTranslation=1: one side tunnels H.245, the other uses a separate H.245
    channel, GnuGk translates between them, both keep their choice and media flows"""
    gk, caller, callee = make_call(start_gk, workdir, "plain", "noauth", media,
                                   tunneling=(tunneling_side == "caller"),
                                   callee_tunneling=(tunneling_side == "callee"),
                                   extra_config={"RoutedMode": {"H245TunnelingTranslation": "1"}})
    assert caller["h245Tunneling"] == (tunneling_side == "caller"), "caller: h245Tunneling=%s" % caller["h245Tunneling"]
    assert callee["h245Tunneling"] == (tunneling_side == "callee"), "callee: h245Tunneling=%s" % callee["h245Tunneling"]
    check_call(gk, caller, callee)
    if media == "h245":	# with fastStart H323Plus may not open the separate H.245 channel at all
        assert pcap.ports_used(capture, topology.GK_IP, "TCP", 31000, 31999), "no separate H.245 channel at GnuGk"


def test_e164_numbers_and_several_aliases(start_gk, workdir):
    """endpoints with an H.323-ID and an E.164 number, the call is made to the number"""
    gk = start_gk()
    caller_ep = Endpoint(workdir, "pub1", "caller,1001")
    callee_ep = Endpoint(workdir, "pub2", "callee,2002")
    callee_ep.start(duration=30)
    try:
        assert gk.wait_registered("callee") and gk.wait_registered("2002"), gk.registrations()
        caller, callee = run_call(gk, caller_ep, "2002", duration=3)[0], callee_ep.wait()
    finally:
        callee_ep.kill()
    assert caller["connected"] and callee["connected"], caller["endReason"]
    assert caller["rtpReceived"] > 100 and callee["rtpReceived"] > 100
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    assert "2002:dialedDigits" in cdrs[0]["dest_info"], cdrs[0]
    assert "1001:dialedDigits" in cdrs[0]["src_info"] and "caller:h323_ID" in cdrs[0]["src_info"], cdrs[0]


def test_call_duration_limit(start_gk, workdir):
    """[CallTable] DefaultCallDurationLimit: the gatekeeper ends the call when the limit is reached"""
    gk = start_gk({"CallTable": {"DefaultCallDurationLimit": "4"}})
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"), duration=20)
    assert caller["connected"] and callee["connected"], caller["endReason"]
    assert caller["endReason"] != "EndedByLocalUser", "the caller hung up itself, the limit didn't work"
    assert callee["endReason"] != "EndedByLocalUser"
    assert 3000 <= caller["durationMs"] <= 8000, caller["durationMs"]
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    assert cdrs[0]["released_by"] == "0", "should be released by the gatekeeper: %s" % cdrs[0]
    assert 3 <= int(cdrs[0]["duration"]) <= 6, cdrs[0]
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("config,reject", [
    ({"RoutedMode": {"TranslateReceivedQ931Cause": "17:=34"}}, "busy"),
    ({"EP::callee": {"TranslateReceivedQ931Cause": "17:=34"}}, "busy"),
    ({"RoutedMode": {"TranslateSentQ931Cause": "21:=34"}}, "denied"),
    ({"EP::caller": {"TranslateSentQ931Cause": "21:=34"}}, "denied"),
], ids=["received-global", "received-endpoint", "sent-global", "sent-endpoint"])
def test_q931_cause_translation(start_gk, workdir, config, reject):
    """the callee's cause (17 or 21) arrives at the caller as 34, the CDR keeps the original cause"""
    gk = start_gk(config)
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", reject=reject), callee_duration=10)
    assert not caller["connected"]
    assert caller["q931Cause"] == 34, caller
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    assert cdrs[0]["cause"] == ("17" if reject == "busy" else "21"), cdrs[0]


def test_caller_hangs_up_while_ringing(start_gk, workdir):
    """the caller gives up before the callee answers: both sides and the gatekeeper clean up"""
    gk = start_gk()
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", answer_delay=20),
                              timeout=3, callee_duration=10)
    assert not caller["connected"] and caller["cleared"], caller
    assert caller["endReason"] == "EndedByLocalUser", caller["endReason"]
    assert callee["callAttempted"] and not callee["connected"] and callee["cleared"], callee
    assert callee["endReason"] == "EndedByCallerAbort", callee["endReason"]
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    assert cdrs[0]["duration"] == "0" and cdrs[0]["released_by"] == "1", cdrs[0]
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("accept", ["0", "1"], ids=["rejected", "accepted"])
def test_unregistered_caller(start_gk, workdir, accept):
    """a caller without registration sends its Setup straight to the gatekeeper's signaling port"""
    gk = start_gk({"RoutedMode": {"AcceptUnregisteredCalls": accept}})
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", no_gk=True), "callee@" + topology.GK_IP,
                              callee=Endpoint(workdir, "pub2", "callee"), callee_duration=12)
    assert not caller["registered"]
    if accept == "0":
        assert not caller["connected"] and caller["cleared"], caller
        assert not callee["callAttempted"], "the call reached the callee"
    else:
        assert caller["connected"] and callee["connected"], caller["endReason"]
        for side, other in ((caller, callee), (callee, caller)):
            assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)
        cdrs = gk.cdrs()
        assert len(cdrs) == 1 and cdrs[0]["caller_ip"] == topology.HOST_IPS["pub1"], cdrs
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("victim", ["callee", "caller"])
def test_endpoint_killed_during_call(start_gk, workdir, victim):
    """kill -9 one party: GnuGk sees the signaling connection close, ends the call for the other side,
    writes the CDR and doesn't keep the call"""
    gk = start_gk()
    callee = Endpoint(workdir, "pub2", "callee").start(duration=40)
    caller = Endpoint(workdir, "pub1", "caller")
    try:
        assert gk.wait_registered("callee")
        caller.start(call="callee", duration=20)
        time.sleep(3)
        assert gk.number_of_calls() == 1
        killed, survivor = (callee, caller) if victim == "callee" else (caller, callee)
        killed.kill()
        result = survivor.wait()
    finally:
        caller.kill()
        callee.kill()
    assert result["connected"] and result["cleared"], result
    assert result["endReason"] != "EndedByLocalUser", "the call should be ended by the other side"
    assert result["durationMs"] < 10000, "the call wasn't ended when the %s died" % victim
    time.sleep(0.5)
    assert gk.number_of_calls() == 0
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and int(cdrs[0]["duration"]) <= 6, cdrs


def test_parallel_calls(start_gk, workdir, capture):
    """5 calls at the same time through the RTP proxy: all connect with media in both directions,
    each gets its own proxy ports"""
    count = 5
    gk = start_gk()
    callees = [Endpoint(workdir, "pub2", "callee%d" % i, instance=i).start(duration=40) for i in range(count)]
    callers = []
    try:
        for i in range(count):
            assert gk.wait_registered("callee%d" % i)
        callers = [Endpoint(workdir, "pub1", "caller%d" % i, instance=i).start(call="callee%d" % i, duration=6)
                   for i in range(count)]
        time.sleep(4)
        assert gk.number_of_calls() == count
        caller_results = [c.wait() for c in callers]
        callee_results = [c.wait() for c in callees]
    finally:
        for ep in callers + callees:
            ep.kill()
    for caller, callee in zip(caller_results, callee_results):
        assert caller["connected"] and callee["connected"], (caller, callee)
        for side, other in ((caller, callee), (callee, caller)):
            assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 200, (side, other)
    proxy_ports = pcap.ports_used(capture, topology.GK_IP, "UDP", 40000, 41999)
    assert len(proxy_ports) >= 2 * count, "calls share proxy ports: %s" % sorted(proxy_ports)
    cdrs = gk.cdrs()
    assert len(cdrs) == count and len({c["callid"] for c in cdrs}) == count, cdrs
    time.sleep(0.5)
    assert gk.number_of_calls() == 0
