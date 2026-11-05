"""H.460.18/.19 behind NATs that forget UDP mappings quickly."""

import contextlib
import time

from harness import gnugk, pcap, topology
from harness.calls import run_call
from harness.endpoint import Endpoint

SHORT_UDP_TIMEOUT = "10"
SYSCTLS = ["net.netfilter.nf_conntrack_udp_timeout", "net.netfilter.nf_conntrack_udp_timeout_stream"]


@contextlib.contextmanager
def short_udp_timeouts(router):
    """the NAT router drops idle UDP mappings after 10 seconds"""
    old = {}
    for key in SYSCTLS:
        old[key] = topology.in_ns(router, "sysctl", "-n", key).stdout.strip()
        topology.in_ns(router, "sysctl", "-qw", "%s=%s" % (key, SHORT_UDP_TIMEOUT))
    try:
        yield
    finally:
        for key, value in old.items():
            topology.in_ns(router, "sysctl", "-qw", "%s=%s" % (key, value))


def test_idle_callee_behind_short_nat_timeout(start_gk, workdir):
    """an H.460.18 callee that was idle for 45 seconds behind a NAT with 10 second UDP timeouts can still
    be called: its keep-alive RRQs keep the RAS mapping open for the SCI"""
    gk = start_gk(gnugk.h46018_config())
    gk.require("h46018")
    with short_udp_timeouts("nat2"):
        callee = Endpoint(workdir, "priv2", "callee", h46018=True, faststart=False).start(duration=90)
        try:
            assert gk.wait_registered("callee")
            time.sleep(45)
            caller, callee_result = run_call(gk, Endpoint(workdir, "pub1", "caller", faststart=False), "callee")
            callee_result = callee.wait()
        finally:
            callee.kill()
    assert caller["connected"] and callee_result["connected"], caller["endReason"]
    for side, other in ((caller, callee_result), (callee_result, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)
    sci = gk.trace_count("serviceControlIndication {")
    assert sci >= 1, "no SCI sent to the callee"


def test_long_call_behind_short_nat_timeout(start_gk, workdir):
    """a 40 second H.460.18 call through a NAT with 10 second UDP timeouts keeps its media"""
    gk = start_gk(gnugk.h46018_config())
    gk.require("h46018")
    with short_udp_timeouts("nat1"):
        caller, callee = run_call(gk, Endpoint(workdir, "priv1", "caller", h46018=True, faststart=False), "callee",
                                  callee=Endpoint(workdir, "pub2", "callee", faststart=False), duration=40)
    assert caller["connected"] and callee["connected"], caller["endReason"]
    assert caller["durationMs"] >= 39000, caller["durationMs"]
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.95 * other["rtpSent"] > 1500, (side, other)


def test_two_h46018_endpoints_behind_same_nat(start_gk, workdir, capture):
    """caller and callee are both behind nat1 and use H.460.18: GnuGk sees both at the same public IP,
    the call goes out through the NAT to the proxy and back in (hairpin), media flows both ways"""
    gk = start_gk(gnugk.h46018_config())
    gk.require("h46018")
    nat_ip = topology.NAT_ROUTERS["nat1"][0]
    caller, callee = run_call(gk, Endpoint(workdir, "priv1", "caller", h46018=True, faststart=False), "callee",
                              callee=Endpoint(workdir, "priv1", "callee", h46018=True, faststart=False),
                              duration=5)
    assert caller["registered"] and callee["registered"]
    assert caller["connected"] and callee["connected"], caller["endReason"]
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpSent"] > 100 and side["rtpReceived"] >= 0.8 * other["rtpSent"], (side, other)

    def proxy(port):
        return 40000 <= port <= 41999
    assert pcap.count(capture, src=nat_ip, dst=topology.GK_IP, dport=proxy) > 200, "media didn't reach the proxy"
    assert pcap.count(capture, src=topology.GK_IP, dst=nat_ip, sport=proxy) > 200, "media didn't come back"
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["cause"] == "16", cdrs
    assert gk.number_of_calls() == 0
