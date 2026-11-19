"""T.120 data channels and [RoutedMode] EnableT120."""

import pytest

from harness import gnugk, topology
from harness.calls import run_call
from harness.endpoint import Endpoint


def describe_params(params):
    """description of the parameters, shown by --describe"""
    if "enabled" not in params:
        return ""
    enabled = {None: "EnableT120 not set (default 1)", "1": "EnableT120=1", "0": "EnableT120=0"}[params["enabled"]]
    return "%s; %s; %s" % (enabled,
                           "H.245 tunneled" if params["tunneling"] else "separate H.245 channel",
                           "RTP proxy on" if params["proxy"] == "1" else "RTP proxy off")


@pytest.mark.parametrize("proxy", ["1", "0"], ids=["proxy", "no-proxy"])
@pytest.mark.parametrize("tunneling", [True, False], ids=["tunneled", "separate-h245"])
@pytest.mark.parametrize("enabled", [None, "1", "0"], ids=["default", "enabled", "disabled"])
def test_t120(start_gk, workdir, enabled, tunneling, proxy):
    """both endpoints offer T.120 in their capability set and open a T.120 channel once the call is up:
    by default the capabilities and the OpenLogicalChannels reach the other side (which has no T.120 and
    rejects the channel), with EnableT120=0 GnuGk removes the capabilities and rejects the channels itself,
    the call and its audio are not affected"""
    config = {"Proxy": {"Enable": proxy}}
    if enabled is not None:
        config["RoutedMode"] = {"EnableT120": enabled}
    gk = start_gk(config)
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", faststart=False, tunneling=tunneling, t120=True),
                              "callee", duration=4,
                              callee=Endpoint(workdir, "pub2", "callee", faststart=False, tunneling=tunneling, t120=True))
    assert caller["connected"] and callee["connected"], caller["endReason"]
    assert caller["h245Tunneling"] == tunneling and callee["h245Tunneling"] == tunneling
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 100, (side, other)
        # the other side has no T.120, so the channel is rejected either way
        assert side["t120OlcRejected"], "%s's T.120 channel wasn't rejected" % side["alias"]
        if enabled == "0":
            assert not side["t120CapReceived"], "%s got a T.120 capability" % side["alias"]
            assert not side["t120OlcReceived"], "%s got a T.120 OpenLogicalChannel" % side["alias"]
        else:
            assert side["t120CapReceived"], "%s didn't get the T.120 capability" % side["alias"]
            assert side["t120OlcReceived"], "%s didn't get the T.120 OpenLogicalChannel" % side["alias"]
    rejected_by_gk = gk.trace_count("Rejecting T.120 channel")
    assert rejected_by_gk == (2 if enabled == "0" else 0), rejected_by_gk
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["cause"] == "16", cdrs


ROUTING = {
    "proxy": {"Proxy": {"Enable": "1"}},
    "h245routed": {"Proxy": {"Enable": "0"}, "RoutedMode": {"H245Routed": "1"}},
    # no H.245 handler: GnuGk only sees tunneled H.245
    "signal-routed": {"Proxy": {"Enable": "0"}, "RoutedMode": {"H245Routed": "0"}},
}


@pytest.mark.parametrize("tunneling", [True, False], ids=["tunneled", "separate-h245"])
@pytest.mark.parametrize("routing", list(ROUTING))
@pytest.mark.parametrize("channel", ["olc", "olca", "olc-encrypted"])
def test_t120_disabled_no_connection(start_gk, workdir, channel, routing, tunneling):
    """with EnableT120=0 a T.120 channel never gets as far as a connection when GnuGk sees the H.245: one side
    opens a T.120 channel with a separate stack address (the gatekeeper's status port, a listener we can see) in
    its OLC (olc, olc-encrypted: as H.235 media channel) or the other side accepts the T.120 channel with it in its
    OLCAck (olca); GnuGk must reject the OLC, so nobody gets a T.120 capability or a separate stack address and
    nobody connects anywhere. That includes tunneled H.245 in signal routed calls, which have no H.245 handler.
    A separate H.245 channel that isn't routed goes directly between the endpoints, GnuGk can't do anything there"""
    if routing == "signal-routed" and not tunneling:
        pytest.skip("H.245 goes directly between the endpoints, GnuGk doesn't see it")
    config = {"Proxy": {"T120PortRange": "33000-33099"}, "RoutedMode": {"EnableT120": "0"}}
    for section, values in ROUTING[routing].items():
        config.setdefault(section, {}).update(values)
    gk = start_gk(config)
    status = "%s:%d" % (topology.GK_IP, gnugk.STATUS_PORT)
    common = dict(faststart=False, tunneling=tunneling, t120=True)
    if channel == "olca":
        caller = Endpoint(workdir, "pub1", "caller", t120_connect=True, **common)
        callee = Endpoint(workdir, "pub2", "callee", t120_ack=True, t120_address=status, **common)
    else:
        caller = Endpoint(workdir, "pub1", "caller", t120_address=status, t120_encrypted=(channel == "olc-encrypted"),
                          **common)
        callee = Endpoint(workdir, "pub2", "callee", t120_connect=True, **common)
    caller, callee = run_call(gk, caller, "callee", duration=4, callee=callee)
    assert caller["connected"] and callee["connected"], caller["endReason"]
    assert caller["h245Tunneling"] == tunneling and callee["h245Tunneling"] == tunneling
    leaks = []
    for side in (caller, callee):
        if side["t120CapReceived"]:
            leaks.append("%s got a T.120 capability" % side["alias"])
        if side["t120OlcReceived"]:
            leaks.append("%s got a T.120 OpenLogicalChannel" % side["alias"])
        if side["t120Connected"]:
            leaks.append("%s made a T.120 connection (answer %r)" % (side["alias"], side["t120Reply"][:40]))
    for ep in ("pub1", "pub2"):
        if gk.trace_count("STATUS\tNew connection from %s:" % topology.HOST_IPS[ep]):
            leaks.append("%s connected to the separate stack address (the status port)" % ep)
    if gk.trace_count("T120\tConnected from") or gk.trace_count("Refusing T.120 connection"):
        leaks.append("GnuGk's T.120 proxy got a connection")
    assert not leaks, "; ".join(leaks)
    assert gk.trace_count("Rejecting T.120 channel") >= 1, "GnuGk didn't reject the T.120 channel"
