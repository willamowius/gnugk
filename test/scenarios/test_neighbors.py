"""Neighbor gatekeepers: which neighbor is asked (SendPrefixes / AcceptPrefixes), forwarded LRQs over three
gatekeepers, a neighbor that is down, LRQ passwords, and a child gatekeeper whose parent restarts."""

import re
import time
from datetime import datetime

import pytest

from harness import topology
from harness.calls import run_call
from harness.endpoint import Endpoint

from scenarios.test_multi_gk import CHILD_CONFIG, check_call, neighbor

GK1, GK2, GK3 = (topology.HOST_IPS[h] for h in ("gk", "gk2", "gk3"))


def merge(*configs):
    """merge {section: {key: value}} dicts (several neighbor() results have the same sections)"""
    result = {}
    for config in configs:
        for section, keys in config.items():
            result.setdefault(section, {}).update(keys)
    return result


def lrq_count(gk, sender=None):
    """LRQs gk received (from sender)"""
    return gk.trace_count("LRQ Received from " + (sender or ""))


def dial(gk, workdir, dialed, name, gk_host="gk", host="pub1", duration=1):
    return run_call(gk, Endpoint(workdir, host, "alice", name="alice-" + name, gk=gk_host), dialed, duration=duration)[0]


def trace_time(gk, text, last=False):
    """the time of the first (last) GnuGk trace line with text, None without one"""
    found = None
    with open(gk.trace_file, errors="replace") as f:
        for line in f:
            if text in line:
                match = re.match(r"(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d{3})", line)
                if match:
                    found = datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S.%f")
                    if not last:
                        break
    return found


# ---- which neighbor is asked

def test_send_and_accept_prefixes(start_gk, workdir):
    """GK1 has the neighbors GK2 (SendPrefixes=2,5:=1, which accepts only 20 and 5 from GK1) and GK3
    (SendPrefixes=3,!39,5:=2): LRQs only go to the neighbor with a matching prefix, not for a '!' prefix and not
    for a number no neighbor has; GK2 refuses an LRQ outside its AcceptPrefixes; for a number both neighbors
    confirm, the neighbor with the better prefix priority gets the call"""
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}},
                   merge(neighbor("GK2", GK2, SendPrefixes="2,5:=1"), neighbor("GK3", GK3, SendPrefixes="3,!39,5:=2")))
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2"}}, neighbor("GK1", GK1, AcceptPrefixes="20,5"),
                   host="gk2", name="gk2")
    gk3 = start_gk({"Gatekeeper::Main": {"Name": "GK3"}}, neighbor("GK1", GK1), host="gk3", name="gk3")
    bob2 = Endpoint(workdir, "pub2", "bob2,2001,2101,5001", gk="gk2").start(duration=120, calls=3)
    bob3 = Endpoint(workdir, "pub2", "bob3,3001,3901,5001", gk="gk3").start(duration=120, calls=3)
    try:
        assert gk2.wait_registered("bob2") and gk3.wait_registered("bob3")
        steps = []
        for number in ("2001", "3001", "3901", "4001", "2101", "5001"):
            caller = dial(gk1, workdir, number, number)
            steps.append((number, caller["connected"], lrq_count(gk2), lrq_count(gk3)))
    finally:
        bob2.kill()
        bob3.kill()
    assert steps[0] == ("2001", True, 1, 0), steps
    assert steps[1] == ("3001", True, 1, 1), steps
    assert steps[2] == ("3901", False, 1, 1), "an LRQ was sent for the excluded prefix 39: %s" % steps
    assert steps[3] == ("4001", False, 1, 1), "an LRQ was sent for a prefix no neighbor has: %s" % steps
    assert steps[4][:2] == ("2101", False) and steps[4][2] > 1 and steps[4][3] == 1, \
        "GK2 should get and refuse the LRQ for 2101: %s" % steps
    assert steps[5][:2] == ("5001", True) and steps[5][3] == 2, steps
    cdrs2, cdrs3 = gk2.cdrs(), gk3.cdrs()
    assert [c["dialed_number"] for c in cdrs2] == ["2001", "5001"], "5001 should go to GK2 (priority 1): %s" % cdrs2
    assert [c["dialed_number"] for c in cdrs3] == ["3001"], cdrs3


# ---- forwarded LRQs

def chain(start_gk, hop_count="2", forward="always", accept_forwarded="1", gk2_extra=None):
    """GK1 - GK2 - GK3 in a row (GK1 and GK3 don't know each other), GK1 sends its LRQs with hop_count"""
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, neighbor("GK2", GK2, ForwardHopCount=hop_count))
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2"}, "RasSrv::LRQFeatures": {"ForwardLRQ": forward}},
                   merge(neighbor("GK1", GK1), neighbor("GK3", GK3)), gk2_extra or {}, host="gk2", name="gk2")
    gk3 = start_gk({"Gatekeeper::Main": {"Name": "GK3"}}, neighbor("GK2", GK2, AcceptForwardedLRQ=accept_forwarded),
                   host="gk3", name="gk3")
    return gk1, gk2, gk3


@pytest.mark.parametrize("hop_count,forward,accept_forwarded,reaches_gk3,connects", [
    ("2", "always", "1", True, True),
    ("2", "depends", "1", True, True),
    ("1", "depends", "1", False, False),
    ("2", "never", "1", False, False),
    ("2", "always", "0", True, False),
], ids=["always", "depends-2-hops", "depends-1-hop", "never", "not-accepted"])
def test_lrq_forwarding(start_gk, workdir, hop_count, forward, accept_forwarded, reaches_gk3, connects):
    """alice at GK1 calls carol at GK3, GK2 in the middle forwards the LRQ: with ForwardLRQ=always, or with
    'depends' when the hop count of the LRQ is above 1, never with 'never'; GK3 ignores a forwarded LRQ with
    AcceptForwardedLRQ=0"""
    gk1, gk2, gk3 = chain(start_gk, hop_count, forward, accept_forwarded)
    carol = Endpoint(workdir, "pub2", "carol", gk="gk3")
    caller, callee = run_call(gk3, Endpoint(workdir, "pub1", "alice", gk="gk"), "carol", callee=carol,
                              duration=2, callee_duration=14)
    assert lrq_count(gk2, GK1) >= 1, "GK1 sent no LRQ to GK2"
    assert (lrq_count(gk3, GK2) >= 1) == reaches_gk3, "LRQs at GK3: %d" % lrq_count(gk3)
    assert caller["connected"] == connects, caller
    if connects:
        check_call(caller, callee)
        assert len(gk3.cdrs()) == 1 and len(gk1.cdrs()) == 1, (gk1.cdrs(), gk3.cdrs())
    for gk in (gk1, gk2, gk3):
        assert gk.number_of_calls() == 0


@pytest.mark.parametrize("loop_detection", ["0", "1"], ids=["hop-count", "LoopDetection"])
def test_lrq_loop(start_gk, workdir, loop_detection):
    """GK1 and GK2 forward every LRQ to each other and nobody knows the destination: the LRQ dies when its hop
    count (10) is used up, or with LoopDetection=1 as soon as a gatekeeper sees it a second time; the caller
    is rejected and both gatekeepers stay up"""
    lrq = {"RasSrv::LRQFeatures": {"ForwardLRQ": "always", "ForwardHopCount": "10", "LoopDetection": loop_detection}}
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, lrq, neighbor("GK2", GK2))
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2"}}, lrq, neighbor("GK1", GK1), host="gk2", name="gk2")
    started = time.time()
    caller = dial(gk1, workdir, "ghost", "ghost")
    elapsed = time.time() - started
    time.sleep(2)
    assert not caller["connected"] and caller["registered"], caller
    assert elapsed < 20, "rejecting the call took %d seconds" % elapsed
    at_gk1, at_gk2 = lrq_count(gk1, GK2), lrq_count(gk2, GK1)
    assert at_gk2 >= 1
    if loop_detection == "1":
        assert at_gk1 + at_gk2 <= 4, "LRQs kept circling: %d at GK1, %d at GK2" % (at_gk1, at_gk2)
    else:
        assert at_gk1 + at_gk2 <= 40, "the hop count didn't stop the loop: %d at GK1, %d at GK2" % (at_gk1, at_gk2)
    assert gk1.alive() and gk2.alive()
    assert gk1.number_of_calls() == 0 and gk2.number_of_calls() == 0


# ---- a neighbor that doesn't answer

@pytest.mark.parametrize("timeout,retries", [("5", "1"), ("10", "3")])
def test_neighbor_down(start_gk, workdir, timeout, retries):
    """the only neighbor doesn't answer: GnuGk sends the LRQ and SendRetries retries, waits NeighborTimeout (in
    1/10 s) for each and then routes the call with the next policy (catchall), not earlier and not much later.
    (The manual calls SendRetries the "number of tries", GnuGk treats it as retries after the first LRQ.)"""
    gk = start_gk({"Gatekeeper::Main": {"Name": "GK1"},
                   "RasSrv::LRQFeatures": {"NeighborTimeout": timeout, "SendRetries": retries},
                   "RoutingPolicy": {"default": "explicit,internal,neighbor,catchall"},
                   "Routing::CatchAll": {"CatchAllAlias": "operator"}},
                  neighbor("GK2", GK2))
    operator = Endpoint(workdir, "pub2", "operator")
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "alice"), "nobody", callee=operator, duration=1)
    assert caller["connected"] and callee["connected"], caller
    asked, answered = trace_time(gk, "ARQ Received from"), trace_time(gk, "\tACF|")
    waited = (answered - asked).total_seconds()
    sends = int(retries) + 1
    expected = int(timeout) / 10.0 * sends
    assert expected - 0.2 <= waited <= expected + 1.5, "waited %.1f s for the neighbor, expected %.1f s" % (waited, expected)
    assert gk.trace_count("locationRequest {") == sends, "LRQs sent: %d" % gk.trace_count("locationRequest {")


# ---- LRQ passwords

@pytest.mark.parametrize("send,accepted", [("secret", True), ("wrong", False), (None, False)],
                         ids=["right-password", "wrong-password", "no-password"])
def test_neighbor_password(start_gk, workdir, send, accepted):
    """GK2 has Password=secret for its neighbor GK1: it only answers GK1's LRQs when they carry a token made
    with that password (GK1: SendPassword), otherwise they are handled like LRQs from strangers and the call
    fails; without Password on GK1's side LRQs from GK2 need no token"""
    extra = {"SendPassword": send} if send else {}
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, neighbor("GK2", GK2, **extra))
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2"}}, neighbor("GK1", GK1, Password="secret"),
                   host="gk2", name="gk2")
    alice = Endpoint(workdir, "pub1", "alice", gk="gk")
    caller, callee = run_call(gk2, alice, "bob", callee=Endpoint(workdir, "pub2", "bob", gk="gk2"), duration=2,
                              callee_duration=14)
    assert lrq_count(gk2, GK1) >= 1, "no LRQ reached GK2"
    assert caller["connected"] == accepted, caller
    assert bool(gk2.ras_events("LCF")) == accepted, gk2.ras_events("LCF")
    if accepted:
        check_call(caller, callee)
    else:
        assert gk2.trace_count("Password required, but no match") >= 1
    # the other direction needs no password
    back, alice_result = run_call(gk1, Endpoint(workdir, "pub2", "bob", gk="gk2", name="bob-calls"), "alice",
                                  callee=Endpoint(workdir, "pub1", "alice", gk="gk", name="alice-called"), duration=2)
    check_call(back, alice_result)


# ---- child gatekeeper, parent restarts

def test_parent_gatekeeper_restart(start_gk, workdir):
    """the parent gatekeeper is stopped and started again: the child notices on its next keep-alive, registers
    again and calls between parent and child work in both directions as before"""
    parent_config = {"Gatekeeper::Main": {"Name": "ParentGK", "TimeToLive": "10"}}
    parent = start_gk(parent_config)
    child = start_gk(CHILD_CONFIG, host="gk2", name="child")
    assert parent.wait_registered("childgk"), "the child didn't register with the parent"
    caller, callee = run_call(child, Endpoint(workdir, "pub1", "alice,1001", gk="gk", name="alice-before"), "2001",
                              callee=Endpoint(workdir, "pub2", "bob,2001", gk="gk2", name="bob-before"), duration=2)
    check_call(caller, callee)

    parent.stop()
    time.sleep(1)
    parent = start_gk(parent_config, name="parent-restarted")
    assert "childgk" not in parent.registrations()
    assert parent.wait_registered("childgk", timeout=40), "the child didn't register with the restarted parent"
    assert child.alive()

    caller, callee = run_call(child, Endpoint(workdir, "pub1", "alice,1001", gk="gk"), "2001",
                              callee=Endpoint(workdir, "pub2", "bob,2001", gk="gk2"), duration=2)
    check_call(caller, callee)
    assert len(parent.cdrs()) == 1 and len(child.cdrs()) == 2, (parent.cdrs(), child.cdrs())
    caller, callee = run_call(parent, Endpoint(workdir, "pub2", "bob,2001", gk="gk2", name="bob-calls"), "1001",
                              callee=Endpoint(workdir, "pub1", "alice,1001", gk="gk", name="alice-called"), duration=2)
    assert caller["connected"] and callee["connected"], caller
    assert parent.trace_count("ARQ Received from " + GK2) >= 1, "the child didn't ask the parent"
