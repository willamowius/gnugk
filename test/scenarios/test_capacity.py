"""Call limits: [EP::...] Capacity and the CapacityControl module, bandwidth limits."""

import time

import pytest

from harness import gnugk, topology
from harness.calls import run_call
from harness.endpoint import Endpoint


def long_call(gk, workdir, caller_host, caller_alias, callee_host, callee_alias, dialed, duration=12):
    """start a call that stays up for duration seconds, returns (caller, callee) endpoints"""
    callee = Endpoint(workdir, callee_host, callee_alias).start(duration=duration + 20)
    assert gk.wait_registered(callee_alias.split(",")[0])
    caller = Endpoint(workdir, caller_host, caller_alias).start(call=dialed, duration=duration)
    return caller, callee


def second_call(gk, workdir, caller_host, caller_alias, dialed):
    return Endpoint(workdir, caller_host, caller_alias).start(call=dialed, duration=2).wait()


def test_endpoint_capacity(start_gk, workdir):
    """[EP::gw] Capacity=1: a second call to the endpoint is rejected while the first one is up"""
    gk = start_gk({"EP::gw": {"Capacity": "1"}})
    caller, gw = long_call(gk, workdir, "pub1", "caller1", "pub2", "gw", "gw")
    try:
        time.sleep(3)
        assert gk.number_of_calls() == 1
        rejected = second_call(gk, workdir, "pub1", "caller2", "gw")
        first = caller.wait()
        gw.wait()	# let it unregister, killed it could still hold the alias when the next gw registers
    finally:
        caller.kill()
        gw.kill()
    assert first["connected"], first
    assert rejected["registered"] and not rejected["connected"], rejected
    arj = [e for e in gk.ras_events("ARJ") if "caller2" in e[3]]
    assert arj, "no ARJ for the second call: %s" % gk.ras_events("ARJ")
    # capacity is free again after the first call
    gw = Endpoint(workdir, "pub2", "gw", name="gw-again").start(duration=20)
    try:
        assert gk.wait_registered("gw")
        again = second_call(gk, workdir, "pub1", "caller2", "gw")
    finally:
        gw.kill()
    assert again["connected"], again


def test_capacity_control(start_gk, workdir):
    """CapacityControl: at most one active call from the caller's IP"""
    gk = start_gk({
        "Gatekeeper::Auth": {"CapacityControl": "required;Setup"},
        "Gatekeeper::Acct": {"CapacityControl": "required;start,stop"},
        "CapacityControl": {"ip:%s/32" % topology.HOST_IPS["pub1"]: "1"},
    })
    caller, callee = long_call(gk, workdir, "pub1", "caller1", "pub2", "callee1", "callee1")
    try:
        callee2 = Endpoint(workdir, "pub2", "callee2").start(duration=20)
        assert gk.wait_registered("callee2")
        time.sleep(3)
        assert gk.number_of_calls() == 1
        rejected = second_call(gk, workdir, "pub1", "caller2", "callee2")
        first = caller.wait()
        callee2.kill()
    finally:
        caller.kill()
        callee.kill()
    assert first["connected"], first
    assert rejected["registered"] and not rejected["connected"], rejected
    assert gk.trace_count("CapacityControl Setup check failed") == 1


def capacity_control(rules, compare_case=None):
    config = {
        "Gatekeeper::Auth": {"CapacityControl": "required;Setup"},
        "Gatekeeper::Acct": {"CapacityControl": "required;start,stop"},
        "CapacityControl": rules,
        # the second caller sends its Setup without registering, so it can use the same H.323 ID or number
        "RoutedMode": {"AcceptUnregisteredCalls": "1"},
    }
    if compare_case is not None:
        config["Gatekeeper::Main"] = {"CompareAliasCase": compare_case}
    return config


def unregistered_call(workdir, host, alias, dialed, name):
    """a call from an unregistered endpoint straight to the gatekeeper's signaling port, returns its result"""
    return Endpoint(workdir, host, alias, no_gk=True, name=name).start(
        call="%s@%s" % (dialed, topology.GK_IP), duration=2).wait()


def call_volume_test(start_gk, workdir, rules, first, second, compare_case=None):
    """first: (caller alias, callee alias, dialed) of the call that stays up, second: [(caller alias, host, dialed)]
    of unregistered calls made meanwhile to the callees 'callee2' and 'callee3,3003'; returns their results"""
    gk = start_gk(capacity_control(rules, compare_case))
    caller, callee = long_call(gk, workdir, "pub1", first[0], "pub2", first[1], first[2])
    others = [Endpoint(workdir, "pub2", "callee2,2002").start(duration=30, calls=3),
              Endpoint(workdir, "pub2", "callee3,3003").start(duration=30, calls=3)]
    try:
        assert gk.wait_registered("callee2") and gk.wait_registered("callee3")
        time.sleep(3)
        assert gk.number_of_calls() == 1, "the first call isn't up"
        results = [unregistered_call(workdir, host, alias, dialed, "second-%d" % i)
                   for i, (alias, host, dialed) in enumerate(second)]
        first_result = caller.wait()
    finally:
        caller.kill()
        callee.kill()
        for ep in others:
            ep.kill()
    assert first_result["connected"], first_result
    return gk, results


def test_capacity_control_h323id(start_gk, workdir):
    """CapacityControl h323id:caller=1: while 'caller' has a call up, a 2nd call from the H.323 ID 'caller' is rejected,
    a call from another H.323 ID isn't limited"""
    gk, (same, other) = call_volume_test(start_gk, workdir, {"h323id:caller": "1"}, ("caller", "callee1", "callee1"),
                                         [("caller", "pub2", "callee2"), ("other", "pub2", "callee3")])
    assert not same["connected"], same
    assert other["connected"], other
    assert gk.trace_count("CapacityControl Setup check failed") == 1


def test_capacity_control_cli_called_pattern(start_gk, workdir):
    """CapacityControl cli:1001=^20 1: one call from CLI 1001 to numbers starting with 20, calls to other numbers
    don't match the rule"""
    gk, (to_20, to_30) = call_volume_test(start_gk, workdir, {"cli:1001": "^20 1"},
                                          ("caller,1001", "callee1,2001", "2001"),
                                          [("second,1001", "pub2", "2002"), ("third,1001", "pub2", "3003")])
    assert not to_20["connected"], to_20
    assert to_30["connected"], to_30


def test_capacity_control_rule_order(start_gk, workdir):
    """IP rules are matched before H.323 ID rules: a call from the IP of 'ip:...=5' isn't limited by h323id:caller=1"""
    gk, (same,) = call_volume_test(start_gk, workdir, {"ip:%s/32" % topology.HOST_IPS["pub2"]: "5", "h323id:caller": "1"},
                                   ("caller", "callee1", "callee1"), [("caller", "pub2", "callee2")])
    assert same["connected"], same


def test_capacity_control_released(start_gk, workdir):
    """the call volume of a rule goes down when a call ends (accounting stop): after the first call a new one passes"""
    gk = start_gk(capacity_control({"ip:%s/32" % topology.HOST_IPS["pub1"]: "1"}))
    for i in range(2):
        caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", name="caller-%d" % i), "callee",
                                  callee=Endpoint(workdir, "pub2", "callee", name="callee-%d" % i))
        assert caller["connected"], (i, caller)
    assert gk.trace_count("CapacityControl Setup check failed") == 0


@pytest.mark.parametrize("compare_case,limited", [("1", False), ("0", True)], ids=["case-sensitive", "case-insensitive"])
def test_capacity_control_alias_case(start_gk, workdir, compare_case, limited):
    """CapacityControl h323id:Caller=1 only applies to the H.323 ID 'caller' with CompareAliasCase=0"""
    gk, (same,) = call_volume_test(start_gk, workdir, {"h323id:Caller": "1"}, ("caller", "callee1", "callee1"),
                                   [("caller", "pub2", "callee2")], compare_case)
    assert same["connected"] != limited, same


def test_total_bandwidth(start_gk, workdir):
    """TotalBandwidth: a second call that doesn't fit is rejected, the bandwidth is free again afterwards"""
    gk = start_gk({"Gatekeeper::Main": {"TotalBandwidth": "1500"}})
    caller, callee = long_call(gk, workdir, "pub1", "caller1", "pub2", "callee1", "callee1")
    try:
        callee2 = Endpoint(workdir, "pub2", "callee2").start(duration=30)
        assert gk.wait_registered("callee2")
        time.sleep(3)
        rejected = second_call(gk, workdir, "pub1", "caller2", "callee2")
        first = caller.wait()
        time.sleep(1)
        again = second_call(gk, workdir, "pub1", "caller2", "callee2")
        callee2.kill()
    finally:
        caller.kill()
        callee.kill()
    assert first["connected"], first
    assert not rejected["connected"], rejected
    assert [e for e in gk.ras_events("ARJ") if e[5] == "requestDenied"], gk.ras_events("ARJ")
    assert again["connected"], "bandwidth not released after the first call: %s" % again


def test_maximum_bandwidth_per_call(start_gk, workdir):
    """MaximumBandwidthPerCall: the ACF grants less than the endpoint asked for"""
    gk = start_gk({"Gatekeeper::Main": {"MaximumBandwidthPerCall": "640"}})
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", bandwidth=1280), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", bandwidth=1280))
    assert caller["connected"] and callee["connected"]
    assert gk.trace_count("ACF will grant bandwidth of 640") == 2
    assert gk.trace_count("ACF will grant bandwidth of 1280") == 0


@pytest.mark.parametrize("auth", ["noauth", "md5"])
@pytest.mark.parametrize("brq,granted", [(1400, "1400"), (2000, "1500")], ids=["fits", "too-much"])
def test_bandwidth_request(start_gk, workdir, auth, brq, granted):
    """BRQ during a call with TotalBandwidth=1500: confirmed with the requested bandwidth when it fits,
    otherwise with what is left (with MD5 the BRQ carries a token and BRQ is checked)"""
    config, users, pw = [{"Gatekeeper::Main": {"TotalBandwidth": "1500"}}], None, {}
    if auth == "md5":
        config.append(gnugk.md5_config())
        users = {"caller": "secretA", "callee": "secretB"}
        pw = {"caller": "secretA", "callee": "secretB"}
    gk = start_gk(*config, users=users)
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", bandwidth=1280, brq=brq, password=pw.get("caller")),
                              "callee", callee=Endpoint(workdir, "pub2", "callee", bandwidth=1280,
                                                        password=pw.get("callee")))
    assert caller["connected"] and callee["connected"]
    assert caller["brqConfirmed"] is True, caller
    bcf = gk.ras_events("BCF")
    assert len(bcf) == 1 and bcf[0][3] == granted, bcf
