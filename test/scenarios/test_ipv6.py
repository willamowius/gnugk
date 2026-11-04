"""IPv6 registration and calls (EnableIPv6=1), also between an IPv4 and an IPv6 endpoint."""

import pytest

from harness import topology
from harness.calls import run_call
from harness.endpoint import Endpoint

pytestmark = pytest.mark.skipif(not topology.IPV6_AVAILABLE, reason="no IPv6 (the kernel has no IPv6 support or GKTEST_IPV6=0)")

IPV6_CONFIG = {"Gatekeeper::Main": {"EnableIPv6": "1", "Home": "%s,%s" % (topology.GK_IP, topology.GK_IP6)}}


@pytest.mark.parametrize("caller_v6,callee_v6", [(True, True), (False, True), (True, False)],
                         ids=["v6-to-v6", "v4-to-v6", "v6-to-v4"])
def test_ipv6_call(start_gk, workdir, caller_v6, callee_v6):
    gk = start_gk(IPV6_CONFIG)
    gk.require("ipv6")
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", ipv6=caller_v6), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", ipv6=callee_v6))
    assert caller["registered"] and callee["registered"]
    assert caller["connected"] and callee["connected"], caller["endReason"]
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)
    cdrs = gk.cdrs()
    assert len(cdrs) == 1, cdrs
    expected_caller = topology.HOST_IPS6["pub1"] if caller_v6 else topology.HOST_IPS["pub1"]
    assert expected_caller in cdrs[0]["caller_ip"], cdrs[0]
    assert caller["unregistered"] and callee["unregistered"]
