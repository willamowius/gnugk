"""Hostile input: malformed RAS and Q.931, oversized ASN.1 arrays, idle connections, and RAS messages that name
somebody else's endpoint or call."""

import random
import socket
import struct
import time

import pytest

from harness import gnugk, netns, topology
from harness.calls import run_call
from harness.endpoint import Endpoint, spoof_ras

GK = topology.GK_IP
ATTACKER = "pub3"


@pytest.fixture
def gnugk_md5():
    return gnugk.md5_config()


def udp_send(host, payloads, port=1719, pause=0.0):
    with netns.entered(host):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for payload in payloads:
            sock.sendto(payload, (GK, port))
            if pause:
                time.sleep(pause)
    finally:
        sock.close()


def check_still_working(gk, workdir, name):
    """GnuGk is up, answers on the status port, registers endpoints and connects a call"""
    assert gk.alive(), "gnugk died"
    assert "Version" in gk.command("Version", "Version:")
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", name="caller-" + name), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", name="callee-" + name), duration=1)
    assert caller["connected"] and callee["connected"], caller


def wait_fds(gk, limit, timeout=30):
    """wait until GnuGk has at most limit open file descriptors, returns the last count"""
    deadline = time.time() + timeout
    while True:
        fds = gk.resources()["fds"]
        if fds <= limit or time.time() > deadline:
            return fds
        time.sleep(1)


# ---- malformed RAS

def rrq_seed(workdir):
    path = workdir + "/rrq.bin"
    spoof_ras(workdir, ATTACKER, "RRQ", alias="seed", dump=path, name="seed")
    return open(path, "rb").read()


def test_malformed_ras(start_gk, workdir):
    """5000 broken RAS datagrams from one host (random bytes, every truncation of a real RRQ, RRQs with random bit
    flips, empty and maximum size datagrams): GnuGk stays up, keeps its memory and file descriptors, and serves
    endpoints"""
    gk = start_gk()
    seed = rrq_seed(workdir)
    assert len(seed) > 20, seed
    check_still_working(gk, workdir, "before")
    before = gk.resources()
    rng = random.Random(4711)
    payloads = [b"", b"\x00" * 65000, bytes(rng.getrandbits(8) for _ in range(65000))]
    payloads += [seed[:n] for n in range(len(seed))]
    for _ in range(3000):
        flipped = bytearray(seed)
        for _ in range(rng.randint(1, 8)):
            flipped[rng.randrange(len(flipped))] ^= 1 << rng.randrange(8)
        payloads.append(bytes(flipped))
    while len(payloads) < 5000:
        payloads.append(bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 400))))
    udp_send(ATTACKER, payloads, pause=0.0005)
    time.sleep(2)
    check_still_working(gk, workdir, "after")
    after = gk.resources()
    assert after["rss_kb"] - before["rss_kb"] < 30000, (before, after)
    assert wait_fds(gk, before["fds"] + 4) <= before["fds"] + 4, (before, gk.resources())
    # bit-flipped RRQs may well register spoofer aliases, but nothing from the attacker may be left in a call
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("count,accepted", [(100, True), (1000, False), (20000, False)])
def test_oversized_alias_array(start_gk, workdir, count, accepted):
    """an RRQ with 100, 1000 or 20000 aliases (MaxASNArraySize defaults to 128): the small one registers, the big
    ones don't get their aliases registered and GnuGk doesn't spend lots of memory on them, and it stays up.
    (1000 is rejected; 20000 needs a fragmented PER length, which PTLib decodes as an empty alias list, so GnuGk
    registers the endpoint under its endpoint ID)"""
    gk = start_gk()
    before = gk.resources()
    reply = spoof_ras(workdir, ATTACKER, "RRQ", alias="many", count=count)
    after = gk.resources()
    if accepted:
        assert reply["reply"] == "registrationConfirm", reply
        assert "many" in gk.registrations() and "many99" in gk.registrations()
    else:
        assert "many" not in gk.registrations() and "many99" not in gk.registrations(), gk.registrations()
        if count < 16384:
            assert reply["reply"] != "registrationConfirm", reply
    assert after["rss_kb"] - before["rss_kb"] < 30000, (before, after)
    check_still_working(gk, workdir, "after")


# ---- malformed call signaling

def tcp_session(payload, wait=1.0):
    """connect to GnuGk's signaling port from the attacker, send payload, return what comes back (b"" when GnuGk
    closes the connection)"""
    sock = netns.connect(ATTACKER, GK, 1720)
    try:
        sock.sendall(payload)
        sock.settimeout(wait)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data
    except OSError:
        return b""
    finally:
        sock.close()


TPKT_CASES = {
    "length-zero": b"\x03\x00\x00\x00",
    "length-short": b"\x03\x00\x00\x03",
    "length-huge": b"\x03\x00\xff\xff" + b"\x08" * 100,
    "bad-version": b"\x09\x00\x00\x10" + b"\x00" * 12,
    "garbage-q931": b"\x03\x00\x00\x40" + b"\xff" * 60,
    "q931-no-uuie": b"\x03\x00\x00\x0c\x08\x02\x00\x01\x05\x04\x03\x80\x90\xa2" [:12],
    "setup-cut-uuie": b"\x03\x00\x00\x20\x08\x02\x00\x01\x05\x7e\x00\x40\x05" + b"\x20" * 19,
    "many-small-tpkts": b"\x03\x00\x00\x05\x08" * 2000,
}


@pytest.mark.parametrize("case", list(TPKT_CASES))
def test_malformed_q931(start_gk, workdir, case):
    """broken TPKT headers and Q.931 messages on the signaling port from a host that isn't registered: GnuGk drops
    the connection (or keeps waiting for the promised bytes) without crashing, and calls still work"""
    gk = start_gk()
    tcp_session(TPKT_CASES[case])
    time.sleep(0.5)
    check_still_working(gk, workdir, case)
    assert gk.number_of_calls() == 0


# every connection keeps a worker thread busy, idle workers are kept for WorkerThreadIdleTimeout (each with a pipe),
# so a short timeout lets the descriptor count settle within the test
SHORT_IDLE = {"Gatekeeper::Main": {"WorkerThreadIdleTimeout": "10"}}


def test_idle_signaling_connections(start_gk, workdir):
    """300 TCP connections to the signaling port that never send anything: calls still work while they are open,
    and once they are closed (and the idle worker threads have timed out) GnuGk's file descriptors go back to
    what they were"""
    gk = start_gk(SHORT_IDLE)
    check_still_working(gk, workdir, "baseline")
    before = gk.resources()
    idle = []
    try:
        for _ in range(300):
            idle.append(netns.connect(ATTACKER, GK, 1720))
        time.sleep(1)
        during = gk.resources()
        check_still_working(gk, workdir, "during")
    finally:
        for sock in idle:
            sock.close()
    assert during["fds"] >= before["fds"] + 250, "the connections didn't reach GnuGk: %s" % during
    fds = wait_fds(gk, before["fds"] + 6, timeout=60)
    assert fds <= before["fds"] + 6, "file descriptors leaked: %d before, %d after" % (before["fds"], fds)
    check_still_working(gk, workdir, "after")


def test_half_open_setup_connections(start_gk, workdir):
    """200 connections that send half a TPKT and stop: GnuGk times them out or keeps them without blocking calls,
    and frees them when they close"""
    gk = start_gk(SHORT_IDLE)
    check_still_working(gk, workdir, "baseline")
    before = gk.resources()
    stalled = []
    try:
        for _ in range(200):
            sock = netns.connect(ATTACKER, GK, 1720)
            sock.sendall(b"\x03\x00\x01\x00\x08\x02")
            stalled.append(sock)
        check_still_working(gk, workdir, "during")
    finally:
        for sock in stalled:
            sock.close()
    fds = wait_fds(gk, before["fds"] + 6, timeout=60)
    assert fds <= before["fds"] + 6, "file descriptors leaked: %d before, %d after" % (before["fds"], fds)


# ---- spoofed RAS

def victim_call(gk, workdir, duration=12, password=None):
    """a call between caller (pub1) and callee (pub2) that stays up, returns (caller, callee, call id)"""
    callee = Endpoint(workdir, "pub2", "callee", password=password and password["callee"]).start(duration=duration + 15)
    assert gk.wait_registered("callee")
    caller = Endpoint(workdir, "pub1", "caller", password=password and password["caller"]).start(
        call="callee", duration=duration)
    deadline = time.time() + 10
    while not gk.call_ids() and time.time() < deadline:
        time.sleep(0.2)
    (call_id,) = gk.call_ids()
    time.sleep(1)
    return caller, callee, call_id


NO_SENDER_CHECK = ("without H.235 tokens the endpoint identifier is the only credential: GnuGk accepts URQ, DRQ, BRQ "
                   "and ARQ with a registered endpoint's ID from any IP (CheckSenderIP only covers ARQs and is off by "
                   "default), so a third party that learns the IDs can unregister the endpoint or end the call record")
PASSWORDS = {"caller": "secretA", "callee": "secretB"}


def spoof_params():
    for kind in ("URQ", "DRQ", "BRQ", "ARQ", "IRR"):
        marks = [pytest.mark.xfail(strict=True, reason=NO_SENDER_CHECK)] if kind != "IRR" else []
        yield pytest.param("none", kind, marks=marks, id="none-" + kind)
    for kind in ("URQ", "DRQ", "BRQ", "ARQ"):
        yield pytest.param("md5", kind, id="md5-" + kind)
    yield pytest.param("CheckSenderIP", "ARQ", id="CheckSenderIP-ARQ")


@pytest.mark.parametrize("protection,kind", list(spoof_params()))
def test_spoofed_ras_with_victims_ids(start_gk, workdir, gnugk_md5, protection, kind):
    """pub3 sends a RAS message with the caller's endpoint ID and the running call's ID: GnuGk rejects or ignores
    it, the caller stays registered with its own address, the call goes on and gets one CDR at its end; with MD5
    tokens required (or CheckSenderIP for ARQs) the missing token (or wrong IP) gives it away"""
    config, password = {}, None
    if protection == "md5":
        config, password = gnugk_md5, PASSWORDS
    elif protection == "CheckSenderIP":
        config = {"RasSrv::ARQFeatures": {"CheckSenderIP": "1"}}
    gk = start_gk(config, users=password)
    caller, callee, call_id = victim_call(gk, workdir, password=password)
    try:
        epid = gk.endpoint_id("caller")
        address = [e["address"] for e in gk.endpoints() if "caller" in e["aliases"]]
        reply = spoof_ras(workdir, ATTACKER, kind, epid, callid=call_id, confid=call_id, alias="callee")
        time.sleep(1)
        registrations, calls = gk.endpoints(), gk.number_of_calls()
        caller_result, callee_result = caller.wait(), callee.wait()
    finally:
        caller.kill()
        callee.kill()
    accepted = {"URQ": "unregistrationConfirm", "DRQ": "disengageConfirm", "BRQ": "bandwidthConfirm",
                "ARQ": "admissionConfirm"}.get(kind)
    assert reply["reply"] != accepted, "the spoofed %s was confirmed: %s" % (kind, reply)
    assert [e["address"] for e in registrations if "caller" in e["aliases"]] == address, \
        "the caller's registration changed: %s" % registrations
    assert calls == 1, "the spoofed %s ended the call" % kind
    assert caller_result["connected"] and caller_result["durationMs"] >= 11000, caller_result
    assert caller_result["endReason"] == "EndedByLocalUser", caller_result
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and int(cdrs[0]["duration"]) >= 10, cdrs


def test_spoofed_ras_unknown_endpoint(start_gk, workdir):
    """RAS messages with an endpoint ID GnuGk never gave out are rejected with notRegistered or ignored"""
    gk = start_gk()
    for kind in ("URQ", "DRQ", "BRQ", "ARQ", "IRR"):
        reply = spoof_ras(workdir, ATTACKER, kind, "1234567_endp", callid="00" * 16, confid="00" * 16, alias="x",
                          name="unknown-" + kind)
        assert reply["reply"] in ("none", "unregistrationReject", "disengageReject", "bandwidthReject",
                                  "admissionReject"), (kind, reply)
    check_still_working(gk, workdir, "after")
