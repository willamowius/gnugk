"""Codec filtering with DisabledCodecs: [CallTable] for all calls, [EP::alias] replaces it for an endpoint's calls."""

import pytest

from harness.calls import run_call
from harness.endpoint import Endpoint

ULAW, ALAW = "G.711-uLaw-64k", "G.711-ALaw-64k"	# the endpoints offer both, u-law first


# what is disabled where -> (config, codec the call must use)
CASES = {
    "none": ({}, ULAW),
    "calltable": ({"CallTable": {"DisabledCodecs": "g711Ulaw64k"}}, ALAW),
    "callee-ep": ({"EP::callee": {"DisabledCodecs": "g711Ulaw64k"}}, ALAW),
    "caller-ep": ({"EP::caller": {"DisabledCodecs": "g711Ulaw64k"}}, ALAW),
    # the endpoint's list replaces the global one (added up, both G.711 codecs would be disabled)
    "ep-replaces-calltable": ({"CallTable": {"DisabledCodecs": "g711Alaw64k"},
                               "EP::callee": {"DisabledCodecs": "g711Ulaw64k"}}, ALAW),
    # both endpoints' lists are used, together they replace the global one
    "both-eps": ({"CallTable": {"DisabledCodecs": "g711Alaw64k"}, "EP::caller": {"DisabledCodecs": "g711Ulaw64k"},
                  "EP::callee": {"DisabledCodecs": "g729"}}, ALAW),
}
CASE_TEXT = {
    "none": "no codec disabled",
    "calltable": "[CallTable] DisabledCodecs=g711Ulaw64k",
    "callee-ep": "[EP::callee] DisabledCodecs=g711Ulaw64k",
    "caller-ep": "[EP::caller] DisabledCodecs=g711Ulaw64k",
    "ep-replaces-calltable": "[CallTable] disables A-law, [EP::callee] u-law: the endpoint's list replaces the global one",
    "both-eps": "[CallTable] disables A-law, [EP::caller] u-law, [EP::callee] g729: both endpoint lists replace the global one",
}


def describe_params(params):
    """description of the parameters, shown by --describe"""
    if "where" not in params:
        return ""
    return "%s; media opened with %s; RTP proxy %s" % (CASE_TEXT[params["where"]],
                                                     "fastStart" if params["media"] == "faststart" else "H.245",
                                                     "on" if params["proxy"] == "1" else "off")


def codec_params():
    for where in CASES:
        for media in ("faststart", "h245"):
            for proxy in ("1", "0"):
                yield pytest.param(where, media, proxy,
                                   id="%s-%s-%s" % (where, media, "proxy" if proxy == "1" else "no-proxy"))


@pytest.mark.parametrize("where,media,proxy", list(codec_params()))
def test_disabled_codecs(start_gk, workdir, where, media, proxy):
    """the endpoints offer G.711 u-law and A-law (u-law preferred): GnuGk removes the disabled codecs from fastStart
    and the capability sets and both directions use the remaining one. [CallTable] DisabledCodecs applies to all
    calls, an endpoint's [EP::...] DisabledCodecs replace it for its calls (both endpoints' lists combined)"""
    config, expected = CASES[where]
    gk = start_gk({"Proxy": {"Enable": proxy}}, config)
    faststart = (media == "faststart")
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", faststart=faststart), "callee", duration=4,
                              callee=Endpoint(workdir, "pub2", "callee", faststart=faststart))
    assert caller["connected"] and callee["connected"], caller["endReason"]
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 100, (side, other)
    codecs = {side["alias"]: (side["txCodec"], side["rxCodec"]) for side in (caller, callee)}
    assert codecs == {"caller": (expected, expected), "callee": (expected, expected)}, codecs
