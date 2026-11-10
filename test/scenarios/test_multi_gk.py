"""Two gatekeepers: neighbors (LRQ/LCF), also with H.460.18 neighbor traversal, and child/parent."""

import time

import pytest

from harness import gnugk, pcap, topology
from harness.calls import run_call
from harness.endpoint import Endpoint


def neighbor(name, host=None, **extra):
    """[RasSrv::Neighbors] + [Neighbor::name] for a GnuGk neighbor that accepts and gets all prefixes"""
    section = {"GatekeeperIdentifier": name, "SendPrefixes": "*", "AcceptPrefixes": "*"}
    if host:
        section["Host"] = host
    section.update(extra)
    return {"RasSrv::Neighbors": {name: "GnuGk"}, "Neighbor::" + name: section}


def check_call(caller, callee):
    assert caller["registered"] and callee["registered"]
    assert caller["connected"] and callee["connected"], caller["endReason"]
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)


@pytest.mark.parametrize("direction", ["gk1-to-gk2", "gk2-to-gk1"])
def test_neighbor_call(start_gk, workdir, direction):
    """alice is registered with GK1, bob with GK2: the gatekeepers find each other's endpoints with LRQs"""
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, neighbor("GK2", topology.HOST_IPS["gk2"]))
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2"}}, neighbor("GK1", topology.GK_IP), host="gk2", name="gk2")
    alice = Endpoint(workdir, "pub1", "alice", gk="gk")
    bob = Endpoint(workdir, "pub2", "bob", gk="gk2")
    if direction == "gk1-to-gk2":
        caller, callee = run_call(gk2, alice, "bob", callee=bob)
        asked, answered = gk1, gk2
    else:
        caller, callee = run_call(gk1, bob, "alice", callee=alice)
        asked, answered = gk2, gk1
    check_call(caller, callee)
    assert answered.trace_count("locationRequest {") >= 1, "no LRQ reached the other gatekeeper"
    assert answered.ras_events("LCF"), "no LCF"
    assert len(gk1.cdrs()) == 1 and len(gk2.cdrs()) == 1, (gk1.cdrs(), gk2.cdrs())


def test_neighbor_call_both_proxied(start_gk, workdir, capture):
    """both gatekeepers route and proxy a neighbor call: Q.931 and RTP between the two gatekeepers run
    between their proxies, alice's media only goes to GK1"""
    gk1_ip, gk2_ip = topology.GK_IP, topology.HOST_IPS["gk2"]
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, neighbor("GK2", gk2_ip))
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2"}}, neighbor("GK1", gk1_ip), host="gk2", name="gk2")
    caller, callee = run_call(gk2, Endpoint(workdir, "pub1", "alice", gk="gk"), "bob",
                              callee=Endpoint(workdir, "pub2", "bob", gk="gk2"), duration=5)
    check_call(caller, callee)

    def proxy(port):
        return 40000 <= port <= 41999
    for src, dst in ((gk1_ip, gk2_ip), (gk2_ip, gk1_ip)):
        assert pcap.count(capture, src=src, dst=dst, sport=proxy, dport=proxy) > 100, \
            "no RTP from the proxy of %s to the proxy of %s" % (src, dst)
    assert pcap.count(capture, "TCP", src=gk1_ip, dst=gk2_ip, dport=lambda p: p == 1720), \
        "GK1 didn't send the Setup to GK2"
    alice = topology.HOST_IPS["pub1"]
    assert pcap.count(capture, src=alice, dst=gk1_ip, dport=proxy) > 100, "alice's RTP didn't go to GK1's proxy"
    for gk in (gk1, gk2):
        cdrs = gk.cdrs()
        assert len(cdrs) == 1 and cdrs[0]["cause"] == "16", cdrs
        assert gk.number_of_calls() == 0


@pytest.mark.parametrize("direction", ["to-client", "from-client"])
def test_neighbor_h46018_traversal(start_gk, workdir, direction):
    """GK2 sits behind a NAT (in priv1, with bob) and is an H.460.18 traversal client of GK1 (the traversal
    server, which doesn't know GK2's address and recognizes it by its password): calls work in both
    directions"""
    gk1 = start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, gnugk.h46018_config(),
                   neighbor("GK2", H46018Server="1", H46018Client="0", AuthUser="gk2user", Password="gk2secret"))
    gk1.require("h46018")
    priv1 = topology.HOST_IPS["priv1"]
    gk2 = start_gk({"Gatekeeper::Main": {"Name": "GK2", "Home": priv1}}, gnugk.h46018_config(),
                   neighbor("GK1", topology.GK_IP, H46018Client="1", H46018Server="0",
                            SendAuthUser="gk2user", SendPassword="gk2secret"),
                   host="priv1", name="gk2")
    # the traversal neighbors are only used after their first SCI/SCR exchange
    deadline = time.time() + 15
    while gk2.trace_count("SCR Received from " + topology.GK_IP) == 0 and time.time() < deadline:
        time.sleep(0.2)
    assert gk2.trace_count("SCR Received from " + topology.GK_IP) > 0, "no SCR from GK1"
    time.sleep(0.5)
    alice = Endpoint(workdir, "pub1", "alice", gk="gk", faststart=False)
    bob = Endpoint(workdir, "priv1", "bob", gk="priv1", faststart=False)
    if direction == "to-client":
        caller, callee = run_call(gk2, alice, "bob", callee=bob)
    else:
        caller, callee = run_call(gk1, bob, "alice", callee=alice)
    check_call(caller, callee)
    assert gk1.trace_count("serviceControlIndication {") >= 1, "no H.460.18 SCI between the gatekeepers"


CHILD_CONFIG = {
    "Gatekeeper::Main": {"Name": "ChildGK"},
    "Endpoint": {"Gatekeeper": topology.GK_IP, "Type": "Gateway", "H323ID": "childgk", "Prefix": "2",
                 "Discovery": "0"},
}


@pytest.mark.parametrize("direction", ["parent-to-child", "child-to-parent"])
def test_child_gatekeeper(start_gk, workdir, direction):
    """GK2 registers with GK1 as a gateway for prefix 2 ([Endpoint] section): calls to 2xxx from the parent
    go to the child, the child sends calls it can't route itself to the parent; both gatekeepers release the
    call on the caller's ReleaseComplete (the child's first short Q.931 segment to the parent, the
    ReleaseComplete, is dropped once and retransmitted, so it always arrives late if the child sends it after
    its DRQ)"""
    parent = start_gk({"Gatekeeper::Main": {"Name": "ParentGK"}})
    child = start_gk(CHILD_CONFIG, host="gk2", name="child")
    assert parent.wait_registered("childgk"), "the child didn't register with the parent"
    alice = Endpoint(workdir, "pub1", "alice,1001", gk="gk")
    bob = Endpoint(workdir, "pub2", "bob,2001", gk="gk2")
    if direction == "parent-to-child":
        caller, callee = run_call(child, alice, "2001", callee=bob)
    else:
        with topology.drop_first_short_tcp("gk2", 1720):
            caller, callee = run_call(parent, bob, "1001", callee=alice)
    for result in (caller, callee):
        assert result["endReason"] not in ("EndedByTransportFail", "EndedByConnectFail"), \
            "%s wasn't released by a ReleaseComplete: %s" % (result["alias"], result["endReason"])
    check_call(caller, callee)
    parent_cdrs, child_cdrs = parent.cdrs(), child.cdrs()
    assert len(parent_cdrs) == 1 and len(child_cdrs) == 1, (parent_cdrs, child_cdrs)
    child_ip = topology.HOST_IPS["gk2"]
    if direction == "parent-to-child":
        assert parent_cdrs[0]["callee_ip"] == child_ip, "the parent didn't route to the child: %s" % parent_cdrs
    else:
        assert parent.trace_count("ARQ Received from " + child_ip) >= 1, "the child didn't ask the parent"
        assert parent_cdrs[0]["caller_ip"] == child_ip, parent_cdrs
