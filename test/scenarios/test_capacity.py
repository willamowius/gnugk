"""Call limits: [EP::...] Capacity and the CapacityControl module, bandwidth limits."""

import time

import pytest

from harness import gnugk, topology
from harness.calls import run_call
from harness.endpoint import Endpoint


def long_call(gk, workdir, caller_host, caller_alias, callee_host, callee_alias, dialed, duration=12):
    """start a call that stays up for duration seconds, returns (caller, callee) endpoints"""
    callee = Endpoint(workdir, callee_host, callee_alias).start(duration=duration + 20)
    assert gk.wait_registered(callee_alias)
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
