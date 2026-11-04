"""Read the gatekeeper host's pcap (see the capture fixture) with tcpdump."""

import re
import subprocess

LINE = re.compile(r"IP6? (\S+)\.(\d+) > (\S+)\.(\d+): (\S+)")


def packets(pcap):
    """[(src ip, src port, dst ip, dst port, 'UDP' or 'TCP'), ...]"""
    out = subprocess.run(["tcpdump", "-nn", "-r", pcap], capture_output=True, text=True).stdout
    result = []
    for line in out.splitlines():
        match = LINE.search(line)
        if match:
            src, sport, dst, dport, kind = match.groups()
            result.append((src, int(sport), dst, int(dport.rstrip(":")), "UDP" if kind.startswith("UDP") else "TCP"))
    return result


def ports_used(pcap, host_ip, proto, low, high):
    """ports in [low, high] on host_ip that saw traffic of protocol proto"""
    used = set()
    for src, sport, dst, dport, kind in packets(pcap):
        if kind != proto:
            continue
        if src == host_ip and low <= sport <= high:
            used.add(sport)
        if dst == host_ip and low <= dport <= high:
            used.add(dport)
    return used


def count(pcap, proto="UDP", src=None, dst=None, sport=None, dport=None):
    """number of packets of protocol proto, src/dst: ip or None for any, sport/dport: a function
    port -> bool or None for any"""
    n = 0
    for s_ip, s_port, d_ip, d_port, kind in packets(pcap):
        if kind == proto and src in (None, s_ip) and dst in (None, d_ip) \
                and (sport is None or sport(s_port)) and (dport is None or dport(d_port)):
            n += 1
    return n
