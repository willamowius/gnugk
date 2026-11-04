"""Media through the RTP proxy beyond the basic call: RTCP, H.460.19 multiplexing."""

import re

import pytest

from harness import pcap, topology
from harness.gnugk import GnuGk
from scenarios.test_calls import PLACEMENTS, check_call, make_call

GK = topology.GK_IP
RTCP_CALL_DURATION = 20	# H323Plus sends its first RTCP sender report after 12 seconds


def proxy_rtcp_port(port):
    return 40000 <= port <= 41999 and port % 2 == 1


def wan_ip(host):
    """the address the gatekeeper sees for a host (its NAT router for the private hosts)"""
    for router, (wan, _, priv) in topology.NAT_ROUTERS.items():
        if priv == host:
            return wan
    return topology.HOST_IPS[host]


def last_trace_value(gk: GnuGk, text):
    values = []
    with open(gk.trace_file, errors="replace") as f:
        for line in f:
            match = re.search(re.escape(text) + r" (\d+)", line)
            if match:
                values.append(int(match.group(1)))
    return values[-1] if values else None


# with H.460.18/.19 the endpoints also send RTCP keep-alives (empty sender reports, every 19 seconds),
# which must not reset the RTCP stats
@pytest.mark.parametrize("placement", ["plain", "h46018-both"])
def test_rtcp_through_proxy(start_gk, workdir, capture, placement):
    """RTCP goes through the RTP proxy in both directions, and with EnableRTCPStats=1 GnuGk reads the
    packet counts from both sides' sender reports"""
    gk, caller, callee = make_call(start_gk, workdir, placement, "noauth", "h245", duration=RTCP_CALL_DURATION,
                                   extra_config={"Proxy": {"EnableRTCPStats": "1"}}, trace=7)
    check_call(gk, caller, callee, duration=RTCP_CALL_DURATION)
    caller_host, _, callee_host, _, _ = PLACEMENTS[placement]
    for host in (caller_host, callee_host):
        ip = wan_ip(host)
        assert pcap.count(capture, src=ip, dst=GK, dport=proxy_rtcp_port), "no RTCP from %s to the proxy" % host
        assert pcap.count(capture, src=GK, dst=ip, sport=proxy_rtcp_port), "no RTCP from the proxy to %s" % host
    # the packet counts from both sides' sender reports (GnuGk's DST values come from the caller's reports,
    # SRC from the callee's), not reset by the H.460.19 RTCP keep-alives (empty sender reports)
    for side, result in (("DST", caller), ("SRC", callee)):
        count = last_trace_value(gk, "SetRTCP_%s_packet_count:" % side)
        assert count is not None, "GnuGk saw no RTCP sender report from the %s" % result["alias"]
        assert 0 < count <= result["rtpSent"], (side, count, result["rtpSent"])



MUX_RTP_PORT, MUX_RTCP_PORT = 3000, 3001	# GnuGk's defaults for RTPMultiplexPort / RTCPMultiplexPort


@pytest.mark.parametrize("placement", ["h46018-caller", "h46018-callee", "h46018-both"])
def test_h46019_multiplexing(start_gk, workdir, capture, placement):
    """[Proxy] RTPMultiplexing=1 and H.460.19 multiplexing endpoints: their RTP and RTCP go to GnuGk's
    multiplex ports, media flows both ways (also to a public endpoint that doesn't multiplex)"""
    gk, caller, callee = make_call(start_gk, workdir, placement, "noauth", "h245", h46019m=True,
                                   duration=RTCP_CALL_DURATION, extra_config={"Proxy": {"RTPMultiplexing": "1"}})
    check_call(gk, caller, callee, duration=RTCP_CALL_DURATION)
    caller_host, caller_h46018, callee_host, callee_h46018, _ = PLACEMENTS[placement]
    for host, h46018 in ((caller_host, caller_h46018), (callee_host, callee_h46018)):
        if not h46018:
            continue
        ip = wan_ip(host)
        assert pcap.count(capture, src=ip, dst=GK, dport=lambda p: p == MUX_RTP_PORT) > 100, \
            "%s didn't send its RTP to the multiplex port" % host
        assert pcap.count(capture, src=ip, dst=GK, dport=lambda p: p == MUX_RTCP_PORT), \
            "%s didn't send RTCP to the multiplex port" % host
