"""More routing: number analysis, alias rewriting, catch-all, gateway selection, prefix capacities, policies per
number and per message, host names in the dns policy, and how calls end on a DRQ."""

import time

import pytest

from harness import topology
from harness.calls import run_call
from harness.endpoint import Endpoint, spoof_ras

from scenarios.test_multi_gk import neighbor
from scenarios.test_routing import gateways

GK = topology.GK_IP
PUB2 = topology.HOST_IPS["pub2"]


def dial(gk, workdir, dialed, name, duration=1, **caller_args):
    """a call from 'caller' (pub1) to dialed, returns the caller's result"""
    return run_call(gk, Endpoint(workdir, "pub1", "caller", name="caller-" + name, **caller_args), dialed,
                    duration=duration)[0]


def arj_reasons(gk):
    return [event[5] for event in gk.ras_events("ARJ")]


# ---- number analysis

def test_number_analysis(start_gk, workdir):
    """numberanalysis policy with 20=4:6: a number that is too short gets an ARJ with incompleteAddress (overlap
    sending), a number that is too long an ARJ with undefinedReason, the right length is routed"""
    gk = start_gk({"RoutingPolicy::OnARQ": {"default": "numberanalysis,internal"},
                   "Routing::NumberAnalysis": {"20": "4:6"}})
    callee = Endpoint(workdir, "pub2", "callee,2001,200,20011234").start(duration=30, calls=3)
    try:
        assert gk.wait_registered("callee")
        short = dial(gk, workdir, "200", "short")
        assert not short["connected"] and arj_reasons(gk) == ["incompleteAddress"], (short, arj_reasons(gk))
        too_long = dial(gk, workdir, "20011234", "long")
        assert not too_long["connected"] and arj_reasons(gk)[1:] == ["undefinedReason"], arj_reasons(gk)
        right = dial(gk, workdir, "2001", "right")
        assert right["connected"], right
        callee_result = callee.wait()
    finally:
        callee.kill()
    assert callee_result["callsConnected"] == 1 and callee_result["calledNumber"] == "2001", callee_result


def test_number_analysis_setup(start_gk, workdir):
    """numberanalysis for calls from unregistered endpoints: a Setup with a number of the wrong length is
    released (no overlap sending), the right length is routed"""
    gk = start_gk({"RoutedMode": {"AcceptUnregisteredCalls": "1"},
                   "RoutingPolicy::OnSetup": {"default": "numberanalysis,internal"},
                   "Routing::NumberAnalysis": {"20": "4:6"}})
    callee = Endpoint(workdir, "pub2", "callee,2001,200").start(duration=30, calls=2)
    try:
        assert gk.wait_registered("callee")
        short = dial(gk, workdir, "200@" + GK, "short", no_gk=True)
        assert not short["connected"], short
        right = dial(gk, workdir, "2001@" + GK, "right", no_gk=True)
        assert right["connected"], right
        callee_result = callee.wait()
    finally:
        callee.kill()
    assert callee_result["callsConnected"] == 1, callee_result
    assert gk.number_of_calls() == 0


# ---- alias rewriting and catch-all

def test_rewrite_alias(start_gk, workdir):
    """[RasSrv::RewriteAlias] sales=callee: a call to 'sales' reaches the endpoint 'callee', other aliases
    aren't touched"""
    gk = start_gk({"RasSrv::RewriteAlias": {"sales": "callee"}})
    callee = Endpoint(workdir, "pub2", "callee").start(duration=30)
    try:
        assert gk.wait_registered("callee")
        unknown = dial(gk, workdir, "support", "unknown")
        rewritten = dial(gk, workdir, "sales", "rewritten")
        callee_result = callee.wait()
    finally:
        callee.kill()
    assert not unknown["connected"], unknown
    assert rewritten["connected"] and callee_result["connected"], rewritten


@pytest.mark.parametrize("target", ["alias", "ip"])
def test_catchall(start_gk, workdir, target):
    """catchall policy at the end of the chain: a call to an unknown destination goes to CatchAllAlias, or to
    CatchAllIP (an endpoint that isn't registered); a call to a registered alias isn't caught"""
    catchall = {"CatchAllAlias": "operator"} if target == "alias" else {"CatchAllIP": PUB2}
    gk = start_gk({"RoutingPolicy": {"default": "explicit,internal,catchall"}, "Routing::CatchAll": catchall})
    operator = Endpoint(workdir, "pub2", "operator", no_gk=(target == "ip"),
                        listen_port=1720 if target == "ip" else None).start(duration=30)
    bob = Endpoint(workdir, "pub2", "bob").start(duration=30)
    try:
        assert gk.wait_registered("bob") and (target == "ip" or gk.wait_registered("operator"))
        direct = dial(gk, workdir, "bob", "known")
        caught = dial(gk, workdir, "nobody", "unknown")
        bob_result, operator_result = bob.wait(), operator.wait()
    finally:
        bob.kill()
        operator.kill()
    assert direct["connected"] and bob_result["connected"], direct
    assert caught["connected"] and operator_result["connected"], (caught, operator_result)
    assert len(gk.cdrs()) == 2 and gk.number_of_calls() == 0


# ---- gateway selection

def calls_per_gateway(gk, workdir, numbers, count=2, duration=25):
    """dial the numbers one after the other with gw0 ... registered, returns for every number the gateway that
    got the call (None if it failed)"""
    gws = gateways(gk, workdir, count, calls=len(numbers), duration=duration)
    got = []
    try:
        for i, number in enumerate(numbers):
            caller = dial(gk, workdir, number, "%d-%s" % (i, number))
            got.append(caller["connected"])
        results = [gw.wait() for gw in gws]
    finally:
        for gw in gws:
            gw.kill()
    where = []
    for number, connected in zip(numbers, got):
        owners = [i for i, r in enumerate(results) if any(c["connected"] and c["calledNumber"] == number
                                                          for c in r["calls"])]
        assert len(owners) == (1 if connected else 0), (number, results)
        where.append("gw%d" % owners[0] if owners else None)
    return where


def test_gateway_longest_prefix(start_gk, workdir):
    """two gateways with prefixes 9 and 91: the longest matching prefix wins, whatever the order"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9", "gw1": "91"}})
    assert calls_per_gateway(gk, workdir, ["9123", "9200", "9199"]) == ["gw1", "gw0", "gw1"]


def test_gateway_blacklist_and_wildcard_prefix(start_gk, workdir):
    """prefix lists with '!' and '.': gw0=9,!92 doesn't get numbers starting with 92 (nobody else has them: the
    call is rejected), gw1=8.1 gets 801 and 871 but not 802"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9,!92", "gw1": "8.1"}})
    where = calls_per_gateway(gk, workdir, ["9100", "9200", "8011", "8712", "8023"], duration=40)
    assert where == ["gw0", None, "gw1", "gw1", None], where


def test_gateway_priority(start_gk, workdir):
    """[EP::...] GatewayPriority: of two gateways with the same prefix the one with the lower value gets all
    calls (round robin only applies between equal priorities)"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9", "gw1": "9"},
                   "EP::gw0": {"GatewayPriority": "2"}, "EP::gw1": {"GatewayPriority": "1"}})
    assert calls_per_gateway(gk, workdir, ["9001", "9002", "9003"]) == ["gw1"] * 3


def test_prefix_priority_over_gateway_priority(start_gk, workdir):
    """a prefix priority (9:=1 against 9:=2) is preferred over the GatewayPriority of the gateways"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9:=1", "gw1": "9:=2"},
                   "EP::gw0": {"GatewayPriority": "2"}, "EP::gw1": {"GatewayPriority": "1"}})
    assert calls_per_gateway(gk, workdir, ["9001", "9002"]) == ["gw0"] * 2


def test_least_used_routing(start_gk, workdir):
    """[RasSrv::ARQFeatures] LeastUsedRouting=1 without round robin: while gw0 has a call, the next call for the
    shared prefix goes to gw1"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9", "gw1": "9"},
                   "RasSrv::ARQFeatures": {"RoundRobinGateways": "0", "LeastUsedRouting": "1"}})
    gws = gateways(gk, workdir, 2, calls=2, duration=25)
    first = Endpoint(workdir, "pub1", "caller1").start(call="9001", duration=7)
    try:
        time.sleep(2.5)
        assert gk.number_of_calls() == 1
        second = dial(gk, workdir, "9002", "second", duration=1)
        first_result = first.wait()
        results = [gw.wait() for gw in gws]
    finally:
        first.kill()
        for gw in gws:
            gw.kill()
    assert first_result["connected"] and second["connected"], (first_result, second)
    assert sorted(r["callsConnected"] for r in results) == [1, 1], results


def test_prefix_capacities(start_gk, workdir):
    """[EP::gw0] PrefixCapacities=^91:=1: while gw0 has a call to 91..., a second call to 91... overflows to
    gw1 (lower prefix priority), a call to 92... still goes to gw0; PrintPrefixCapacities shows the counter"""
    gk = start_gk({"RasSrv::GWPrefixes": {"gw0": "9:=1", "gw1": "9:=2"}, "EP::gw0": {"PrefixCapacities": "^91:=1"}})
    gws = gateways(gk, workdir, 2, calls=3, duration=25)
    epids = {gk.endpoint_id("gw0"): "gw0", gk.endpoint_id("gw1"): "gw1"}
    first = Endpoint(workdir, "pub1", "caller1").start(call="9100", duration=9)
    try:
        time.sleep(2.5)
        used = gk.send("PrintPrefixCapacities gw0")
        assert "prefix/capacity/curr: ^91/1/1" in used, used
        overflow = dial(gk, workdir, "9111", "overflow")
        other = dial(gk, workdir, "9222", "other")
        first_result = first.wait()
        time.sleep(0.5)
        free = gk.send("PrintPrefixCapacities gw0")
    finally:
        first.kill()
        for gw in gws:
            gw.kill()
    assert first_result["connected"] and overflow["connected"] and other["connected"], (first_result, overflow, other)
    # the gateways had calls at the same time, so take the destinations from the CDRs
    where = {cdr["dialed_number"]: epids.get(cdr["callee_epid"]) for cdr in gk.cdrs()}
    assert where == {"9100": "gw0", "9111": "gw1", "9222": "gw0"}, gk.cdrs()
    assert "prefix/capacity/curr: ^91/1/0" in free, free


# ---- routing policies per number and per message

def test_routing_policy_per_prefix(start_gk, workdir):
    """[RoutingPolicy] 77=catchall, h323_ID=internal, default=explicit,internal: only numbers starting with 77
    reach the catch-all endpoint, other unknown numbers and names are rejected"""
    gk = start_gk({"RoutingPolicy": {"77": "catchall", "h323_ID": "internal", "default": "explicit,internal"},
                   "Routing::CatchAll": {"CatchAllAlias": "operator"}})
    operator = Endpoint(workdir, "pub2", "operator").start(duration=30)
    try:
        assert gk.wait_registered("operator")
        other_number = dial(gk, workdir, "8812", "88")
        name = dial(gk, workdir, "nobody", "name")
        caught = dial(gk, workdir, "7712", "77")
        operator_result = operator.wait()
    finally:
        operator.kill()
    assert not other_number["connected"] and not name["connected"], (other_number, name)
    assert caught["connected"] and operator_result["connected"], caught
    assert arj_reasons(gk) == ["calledPartyNotRegistered"] * 2, arj_reasons(gk)


def test_routing_policy_per_message(start_gk, workdir):
    """[RoutingPolicy::OnARQ] and [RoutingPolicy::OnSetup]: an unknown destination is rejected for a registered
    caller (ARQ: explicit,internal) and goes to the catch-all endpoint for an unregistered caller (Setup:
    internal,catchall)"""
    gk = start_gk({"RoutedMode": {"AcceptUnregisteredCalls": "1"},
                   "RoutingPolicy::OnARQ": {"default": "explicit,internal"},
                   "RoutingPolicy::OnSetup": {"default": "internal,catchall"},
                   "Routing::CatchAll": {"CatchAllAlias": "operator"}})
    operator = Endpoint(workdir, "pub2", "operator").start(duration=30)
    try:
        assert gk.wait_registered("operator")
        registered = dial(gk, workdir, "nobody", "registered")
        unregistered = dial(gk, workdir, "nobody@" + GK, "unregistered", no_gk=True)
        operator_result = operator.wait()
    finally:
        operator.kill()
    assert not registered["connected"], registered
    assert unregistered["connected"] and operator_result["connected"], unregistered


# ---- dns policy with host names

def test_dns_policy_host_name(start_gk, workdir):
    """dns policy: a call to bob@pub2 (a host name from the hosts file) goes to the unregistered endpoint on that
    host, a call to a host name that doesn't resolve is rejected"""
    gk = start_gk({"RoutingPolicy": {"default": "explicit,internal,dns"}})
    bob = Endpoint(workdir, "pub2", "bob", no_gk=True, listen_port=1720).start(duration=30)
    try:
        started = time.time()
        unknown = dial(gk, workdir, "bob@no-such-host.invalid", "unknown-host")
        lookup_time = time.time() - started
        known = dial(gk, workdir, "bob@pub2", "host")
        bob_result = bob.wait()
    finally:
        bob.kill()
    assert not unknown["connected"], unknown
    assert lookup_time < 15, "rejecting an unknown host name took %d seconds" % lookup_time
    assert known["connected"] and bob_result["connected"], known
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["callee_ip"] == PUB2, cdrs


@pytest.mark.parametrize("resolve", ["1", "0"])
def test_dns_policy_resolve_non_local_lrq(start_gk, workdir, resolve):
    """[Routing::DNS] ResolveNonLocalLRQ: GK2 gets an LRQ from its neighbor GK1 for bob@pub2 and only resolves
    the foreign host name with 1 (the default), with 0 it answers LRJ and the call fails"""
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, neighbor("GK2", topology.HOST_IPS["gk2"]))
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2"}, "RoutingPolicy": {"default": "explicit,internal,dns"},
                    "Routing::DNS": {"ResolveNonLocalLRQ": resolve}},
                   neighbor("GK1", GK), host="gk2", name="gk2")
    bob = Endpoint(workdir, "pub2", "bob", no_gk=True, listen_port=1720).start(duration=20)
    try:
        caller = dial(gk1, workdir, "bob@pub2", "alice")
        bob_result = bob.wait() if resolve == "1" else None
    finally:
        bob.kill()
    assert gk2.trace_count("locationRequest {") >= 1, "no LRQ reached GK2"
    assert caller["connected"] == (resolve == "1"), caller
    assert bool(gk2.ras_events("LCF")) == (resolve == "1") and bool(gk2.ras_events("LRJ")) == (resolve == "0")
    if resolve == "1":
        assert bob_result["connected"], bob_result


# ---- calls ended by a DRQ

@pytest.mark.parametrize("remove,release,ends", [
    ("1", "1", "released"),
    ("1", "0", "closed"),
    ("0", "0", None),
], ids=["release-complete", "default", "RemoveCallOnDRQ-off"])
def test_drq_in_routed_mode(start_gk, workdir, remove, release, ends):
    """a DRQ for a routed call arrives before any ReleaseComplete (sent here for the caller, from its IP):
    by default GnuGk removes the call and closes the signaling channels, with SendReleaseCompleteOnDRQ=1 both
    sides get a ReleaseComplete (cause 16) first, with RemoveCallOnDRQ=0 the call goes on until the caller hangs
    up; in the first two cases both endpoints lose the call right away (a closed channel, or a ReleaseComplete
    GnuGk sends when it notices the other channel is gone)"""
    gk = start_gk({"RoutedMode": {"RemoveCallOnDRQ": remove, "SendReleaseCompleteOnDRQ": release}})
    callee = Endpoint(workdir, "pub2", "callee").start(duration=30)
    caller = Endpoint(workdir, "pub1", "caller")
    try:
        assert gk.wait_registered("callee")
        caller.start(call="callee", duration=8)
        time.sleep(3)
        (call_id,) = gk.call_ids()
        reply = spoof_ras(workdir, "pub1", "DRQ", gk.endpoint_id("caller"), callid=call_id, confid=call_id)
        assert reply["reply"] == "disengageConfirm", reply
        time.sleep(1)
        calls_after_drq = gk.number_of_calls()
        caller_result, callee_result = caller.wait(), callee.wait()
    finally:
        caller.kill()
        callee.kill()
    assert caller_result["connected"] and callee_result["connected"], caller_result
    if ends is None:
        assert calls_after_drq == 1, "the DRQ ended the call"
        assert caller_result["durationMs"] >= 7500 and caller_result["endReason"] == "EndedByLocalUser", caller_result
        assert callee_result["endReason"] == "EndedByRemoteUser", callee_result
    else:
        assert calls_after_drq == 0, "the call is still there after the DRQ"
        for result in (caller_result, callee_result):
            assert 2500 <= result["durationMs"] <= 5500, result
            if ends == "released":
                assert result["endReason"] == "EndedByRemoteUser" and result["q931Cause"] == 16, result
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    assert gk.wait_no_calls()


def test_direct_mode_dead_endpoints(start_gk, workdir):
    """direct mode, both endpoints die without a DRQ: the call stays until their registrations expire (TimeToLive),
    then GnuGk removes it and writes the CDR"""
    gk = start_gk({"RoutedMode": {"GKRouted": "0", "H245Routed": "0"}, "Proxy": {"Enable": "0"},
                   "Gatekeeper::Main": {"TimeToLive": "10"}, "RasSrv::RRQFeatures": {"IRQPollCount": "0"}})
    callee = Endpoint(workdir, "pub2", "callee").start(duration=60)
    caller = Endpoint(workdir, "pub1", "caller")
    try:
        assert gk.wait_registered("callee")
        caller.start(call="callee", duration=60)
        time.sleep(3)
        assert gk.number_of_calls() == 1
    finally:
        caller.kill()
        callee.kill()
    time.sleep(2)
    assert gk.number_of_calls() == 1, "nobody told the gatekeeper, the call should still be there"
    assert gk.wait_no_calls(timeout=90), "the call outlived the registrations: %s" % gk.current_calls()
    assert not ({"caller", "callee"} & gk.registrations())
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and int(cdrs[0]["duration"]) >= 3, cdrs
