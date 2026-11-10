"""What GnuGk does to the call signaling: rewritten information elements, fastStart and H.245 tunneling
switched off, the call rate limit, user input and channels that are closed and reopened during a call."""

import socket
import time

import pytest

from harness import netns, pcap, topology
from harness.calls import run_call
from harness.endpoint import Endpoint

GK = topology.GK_IP


def call(start_gk, workdir, config, caller=None, callee=None, dialed="callee", duration=3,
         caller_alias="caller,1001", callee_alias="callee,2001"):
    """a call from pub1 to pub2 with the given GnuGk config, caller / callee: more Endpoint arguments"""
    gk = start_gk(config)
    caller_result, callee_result = run_call(
        gk, Endpoint(workdir, "pub1", caller_alias, **(caller or {})), dialed,
        callee=Endpoint(workdir, "pub2", callee_alias, **(callee or {})), duration=duration)
    assert caller_result["connected"] and callee_result["connected"], (caller_result, callee_result)
    return gk, caller_result, callee_result


def check_media(caller, callee):
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)


# ---- rewritten information elements

@pytest.mark.parametrize("config,setup_display,connect_display", [
    ({"ScreenDisplayIE": "MyID"}, "MyID", "MyID"),
    ({"ScreenDisplayIE": "MyID", "AppendToDisplayIE": "-GK"}, "MyID-GK", "MyID-GK"),
    ({"ScreenDisplayIE": "Calling", "AppendToDisplayIE": "-x"}, "1001-x", None),
    ({"ScreenDisplayIE": "Called", "AppendToDisplayIE": "-x"}, None, "2001-x"),
    ({"ScreenDisplayIE": "CallingCalled"}, "1001", "2001"),
    ({"ScreenDisplayIE": "Delete"}, "", ""),
    pytest.param({"ScreenDisplayIE": "MyID", "PrependToDisplayIE": "GK "}, "GK MyID", "GK MyID",
                 marks=pytest.mark.xfail(strict=True, reason="PrependToDisplayIE is in the manual and in the list "
                                         "of known config keys, but no code reads it")),
], ids=["fixed", "fixed-append", "calling", "called", "calling-called", "delete", "prepend"])
def test_screen_display_ie(start_gk, workdir, config, setup_display, connect_display):
    """[RoutedMode] ScreenDisplayIE: the Display IE the callee gets in the Setup and the caller gets in the
    Connect is replaced by the fixed text, the calling / called station ID (with AppendToDisplayIE /
    PrependToDisplayIE) or removed; None: the endpoint's own Display IE passes"""
    gk, caller, callee = call(start_gk, workdir, {"RoutedMode": config}, dialed="2001")
    assert callee["display"] == (setup_display if setup_display is not None else "caller"), callee["display"]
    assert caller["display"] == (connect_display if connect_display is not None else "callee"), caller["display"]


def test_display_ie_unchanged_by_default(start_gk, workdir):
    """without ScreenDisplayIE the endpoints' own Display IEs reach the other side"""
    gk, caller, callee = call(start_gk, workdir, {}, dialed="2001")
    assert callee["display"] == "caller" and caller["display"] == "callee", (callee["display"], caller["display"])


@pytest.mark.parametrize("config,expected", [
    ({"ScreenCallingPartyNumberIE": "0965123456"}, "0965123456"),
    ({"ScreenCallingPartyNumberIE": "RegisteredAlias"}, "1001"),
    ({"ScreenCallingPartyNumberIE": "RegisteredAlias", "PrependToCallingPartyNumberIE": "0049",
      "AppendToCallingPartyNumberIE": "99"}, "0049100199"),
], ids=["fixed", "registered-alias", "prepend-append"])
def test_screen_calling_party_number_ie(start_gk, workdir, config, expected):
    """[RoutedMode] ScreenCallingPartyNumberIE: the callee sees the configured number, or with
    RegisteredAlias the caller's registered E.164 number with the configured prefix and suffix"""
    gk, caller, callee = call(start_gk, workdir, {"RoutedMode": config}, dialed="2001")
    assert callee["callingNumber"] == expected, callee


def test_screen_source_address(start_gk, workdir):
    """[RoutedMode] ScreenSourceAddress: the sourceAddress of the Setup the callee gets only has that alias"""
    gk, caller, callee = call(start_gk, workdir, {}, dialed="2001")
    assert "caller" in callee["sourceAliases"].split(","), callee["sourceAliases"]
    gk.stop()
    gk, caller, callee = call(start_gk, workdir, {"RoutedMode": {"ScreenSourceAddress": "MyID"}}, dialed="2001")
    assert callee["sourceAliases"] == "MyID", callee["sourceAliases"]


@pytest.mark.parametrize("config,called_ton,calling_ton", [
    ({}, None, None),
    ({"RoutedMode": {"CalledTypeOfNumber": "1", "CallingTypeOfNumber": "2"}}, 1, 2),
    ({"EP::callee": {"CalledTypeOfNumber": "4", "CallingTypeOfNumber": "3"}}, 4, 3),
    ({"RoutedMode": {"CalledTypeOfNumber": "1", "CallingTypeOfNumber": "2"},
      "EP::callee": {"CalledTypeOfNumber": "4"}}, 4, 2),
], ids=["default", "global", "endpoint", "endpoint-over-global"])
def test_type_of_number(start_gk, workdir, config, called_ton, calling_ton):
    """CalledTypeOfNumber / CallingTypeOfNumber in [RoutedMode] and in the called endpoint's [EP::...] section set
    the type of number of the Setup's called and calling party number IEs, the endpoint's setting wins;
    without them the caller's types pass"""
    gk = start_gk({})
    _, baseline = run_call(gk, Endpoint(workdir, "pub1", "caller,1001", name="caller-base"), "2001",
                           callee=Endpoint(workdir, "pub2", "callee,2001", name="callee-base"), duration=1)
    assert baseline["connected"], baseline
    assert baseline["calledTON"] >= 0 and baseline["callingTON"] >= 0, "no number IEs in the Setup: %s" % baseline
    gk.stop()
    gk, caller, callee = call(start_gk, workdir, config, dialed="2001", duration=1)
    assert callee["calledNumber"] == "2001" and callee["callingNumber"] == "1001", callee
    assert callee["calledTON"] == (called_ton if called_ton is not None else baseline["calledTON"]), callee
    assert callee["callingTON"] == (calling_ton if calling_ton is not None else baseline["callingTON"]), callee


# ---- fastStart and H.245 tunneling switched off by the gatekeeper

@pytest.mark.parametrize("disable", ["0", "1"], ids=["default", "disabled"])
def test_disable_faststart(start_gk, workdir, disable):
    """[RoutedMode] DisableFastStart=1: GnuGk removes the fastStart elements, two endpoints that both offer
    fastStart open their media with H.245 instead and media flows"""
    gk, caller, callee = call(start_gk, workdir, {"RoutedMode": {"DisableFastStart": disable}})
    assert caller["fastStart"] == callee["fastStart"] == (disable == "0"), (caller["fastStart"], callee["fastStart"])
    check_media(caller, callee)
    assert gk.number_of_calls() == 0


@pytest.mark.parametrize("disable", ["0", "1"], ids=["default", "disabled"])
def test_disable_h245_tunneling(start_gk, workdir, capture, disable):
    """[RoutedMode] DisableH245Tunneling=1: two endpoints that both offer tunneling use a separate H.245
    channel through the gatekeeper, media flows"""
    gk, caller, callee = call(start_gk, workdir, {"RoutedMode": {"DisableH245Tunneling": disable}},
                              caller={"faststart": False}, callee={"faststart": False})
    assert caller["h245Tunneling"] == callee["h245Tunneling"] == (disable == "0"), (caller, callee)
    check_media(caller, callee)
    h245_ports = pcap.ports_used(capture, GK, "TCP", 31000, 31999)
    assert bool(h245_ports) == (disable == "1"), h245_ports


# ---- call rate limit

def connection_closed(sock, wait=0.7):
    """True if GnuGk closes the connection within wait seconds"""
    sock.settimeout(wait)
    try:
        return sock.recv(1) == b""
    except socket.timeout:
        return False
    except OSError:
        return True


def test_cps_limit(start_gk, workdir):
    """[RoutedMode] CpsLimit=1 with CpsCheckInterval=1: of 6 connections to the signaling port within a second
    the first ones are accepted and the rest closed at once (no H.323 message), after a pause connections and
    a call are accepted again"""
    gk = start_gk({"RoutedMode": {"CpsLimit": "1", "CpsCheckInterval": "1"}})
    # status port connections (start_gk() checks the port) count as well, let them leave the 2 second window,
    # then start right after a second begins, so all connections fall into the same second
    time.sleep(2.5)
    time.sleep(1.05 - time.time() % 1)
    burst = [netns.connect("pub1", GK, 1720) for _ in range(6)]
    closed = [connection_closed(s) for s in burst]
    for s in burst:
        s.close()
    assert not closed[0], "the first connection was rejected"
    assert 3 <= sum(closed) <= 4, "expected 2 or 3 accepted connections (the limit applies above interval * " \
        "limit connections): %s" % closed
    assert gk.trace_count("Rate limit reached") == sum(closed)
    time.sleep(3)
    single = netns.connect("pub1", GK, 1720)
    assert not connection_closed(single), "still rejecting after the burst"
    single.close()
    # a call, without asking the status port in between (its connections count as well, see below)
    callee = Endpoint(workdir, "pub2", "callee").start(duration=15)
    time.sleep(3)
    caller = Endpoint(workdir, "pub1", "caller").start(call="callee", duration=2)
    try:
        caller_result, callee_result = caller.wait(), callee.wait()
    finally:
        caller.kill()
        callee.kill()
    assert caller_result["connected"] and callee_result["connected"], caller_result
    assert gk.alive()


@pytest.mark.xfail(strict=True, reason="TCPServer::ReadSocket() counts and limits every TCP listener of the gatekeeper, "
                   "so status port connections use up the call rate (and are rejected themselves)")
def test_cps_limit_ignores_status_port(start_gk, workdir):
    """CpsLimit is a limit for calls: status port connections don't count, a connection to the signaling port
    right after 5 status port connections is accepted"""
    gk = start_gk({"RoutedMode": {"CpsLimit": "1", "CpsCheckInterval": "1"}})
    time.sleep(1.05 - time.time() % 1)
    status = [netns.connect("pub1", GK, 7000) for _ in range(5)]
    signaling = netns.connect("pub1", GK, 1720)
    try:
        assert not connection_closed(signaling), "a call was rejected because of status port connections"
        assert not any(connection_closed(s, 0.1) for s in status), "status port connections were rejected"
    finally:
        for s in status + [signaling]:
            s.close()


# ---- user input

@pytest.mark.parametrize("tunneling", [True, False], ids=["tunneled", "separate-h245"])
@pytest.mark.parametrize("mode", ["string", "tone", "q931"])
def test_user_input(start_gk, workdir, mode, tunneling):
    """user input passes through the gatekeeper in both directions: as H.245 UserInputIndication
    (alphanumeric or signal) and as keypad IE in a Q.931 Information message"""
    gk, caller, callee = call(
        start_gk, workdir, {}, duration=4,
        caller={"user_input": "123#", "user_input_mode": mode, "tunneling": tunneling, "faststart": False},
        callee={"user_input": "456*", "user_input_mode": mode, "tunneling": tunneling, "faststart": False})
    assert callee["userInput"] == "123#", "callee got %r" % callee["userInput"]
    assert caller["userInput"] == "456*", "caller got %r" % caller["userInput"]
    check_media(caller, callee)


# ---- channels closed and reopened during the call

@pytest.mark.parametrize("tunneling", [True, False], ids=["tunneled", "separate-h245"])
@pytest.mark.parametrize("proxy", ["1", "0"], ids=["proxy", "noproxy"])
def test_pause_and_resume(start_gk, workdir, capture, proxy, tunneling):
    """the caller sends an empty capability set 3 seconds into the call and the full one 2 seconds later: the
    callee closes its channel (no media for the caller during the pause), opens it again and the media
    reaches the caller again, through the RTP proxy if it is on"""
    gk, caller, callee = call(
        start_gk, workdir, {"Proxy": {"Enable": proxy}}, duration=9,
        caller={"pause_after": 3, "faststart": False, "tunneling": tunneling},
        callee={"faststart": False, "tunneling": tunneling})
    assert caller["paused"], caller
    before, during, after = (caller["rtpReceivedAtPause"], caller["rtpReceivedAtResume"] - caller["rtpReceivedAtPause"],
                             caller["rtpReceived"] - caller["rtpReceivedAtResume"])
    assert before > 100, "no media before the pause: %s" % caller
    assert during < 25, "the callee kept sending during the pause (%d packets)" % during
    assert after > 100, "the media didn't come back after the pause (%d packets): %s" % (after, caller)
    # the caller's own channel stays open all the time
    assert callee["rtpReceived"] >= 0.8 * caller["rtpSent"] > 300, (caller, callee)
    assert caller["endReason"] == "EndedByLocalUser", caller
    assert bool(pcap.ports_used(capture, GK, "UDP", 40000, 41999)) == (proxy == "1")
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and int(cdrs[0]["duration"]) >= 8, cdrs
    assert gk.number_of_calls() == 0
