"""T.120 data channels and [RoutedMode] EnableT120."""

import pytest

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
