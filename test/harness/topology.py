"""Network namespaces for the GnuGk test harness.

Every host runs in its own network namespace. All public hosts hang on one
bridge (in its own namespace), the NATed endpoints sit behind a router
namespace that masquerades their traffic:

    gk     10.99.0.1  --+
    gk2    10.99.0.2  --+
    gk3    10.99.0.3  --+
    pub1   10.99.0.11 --+
    pub2   10.99.0.12 --+-- bridge
    pub3   10.99.0.13 --+
    nat1   10.99.0.21 --+     nat1 lan 192.168.1.1 -- priv1 192.168.1.10
    nat2   10.99.0.22 --+     nat2 lan 192.168.2.1 -- priv2 192.168.2.10

The public hosts have no route to the private networks, so the only way to
reach a private endpoint is through state its NAT router created when the
endpoint sent something out (which is what H.460.18/.19 relies on).
"""

import contextlib
import os
import shutil
import subprocess

PREFIX = "gkt-"
BRIDGE_NS = PREFIX + "core"

GK_IP = "10.99.0.1"

# name -> (wan ip, lan network prefix or None)
PUBLIC_HOSTS = {
    "gk": GK_IP,
    "gk2": "10.99.0.2",	# a second gatekeeper (neighbor, child)
    "gk3": "10.99.0.3",	# a third gatekeeper (LRQ forwarding)
    "pub1": "10.99.0.11",
    "pub2": "10.99.0.12",
    "pub3": "10.99.0.13",	# a third party: attacker, HTTP server, transfer target
}
NAT_ROUTERS = {
    "nat1": ("10.99.0.21", "192.168.1", "priv1"),
    "nat2": ("10.99.0.22", "192.168.2", "priv2"),
}

# IPv6 addresses of the hosts on the bridge (IPv6 is only used on the bridge, not behind the NATs),
# only set up when the kernel supports IPv6 (GKTEST_IPV6=0 turns it off)
IPV6_AVAILABLE = os.path.exists("/proc/net/if_inet6") and os.environ.get("GKTEST_IPV6", "1") != "0"
GK_IP6 = "fd00:99::1"
HOST_IPS6 = {"gk": GK_IP6, "pub1": "fd00:99::11", "pub2": "fd00:99::12"}

# the address an endpoint uses for signaling and RAS, by host name
HOST_IPS = dict(PUBLIC_HOSTS)
HOST_IPS.update({priv: lan + ".10" for (_, lan, priv) in NAT_ROUTERS.values()})


def ns(host):
    return PREFIX + host


def _run(*args, check=True):
    return subprocess.run(list(args), check=check, capture_output=True, text=True)


def ip(*args, check=True):
    return _run("ip", *args, check=check)


def in_ns(host, *args, check=True):
    return _run("ip", "netns", "exec", ns(host), *args, check=check)


def existing_namespaces():
    out = ip("netns", "list").stdout
    return [line.split()[0] for line in out.splitlines() if line.startswith(PREFIX)]


def namespace_pids(name):
    """processes running in a test namespace (name with prefix)"""
    out = ip("netns", "pids", name, check=False).stdout
    return [int(pid) for pid in out.split() if pid.isdigit()]


def kill_leftovers():
    """kill every process still running in a test namespace, returns [(namespace, pid, command)]"""
    import signal
    import time
    killed = []
    for name in existing_namespaces():
        for pid in namespace_pids(name):
            try:
                with open("/proc/%d/cmdline" % pid, "rb") as f:
                    cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
                os.kill(pid, signal.SIGKILL)
                killed.append((name, pid, cmd))
            except (OSError, ProcessLookupError):
                pass
    deadline = time.time() + 5
    while killed and time.time() < deadline and any(namespace_pids(n) for n in {k[0] for k in killed}):
        time.sleep(0.1)
    return killed


def sockets(host):
    """TCP and UDP sockets of a host (ss output), with their processes"""
    return in_ns(host, "ss", "-tuanp", check=False).stdout


@contextlib.contextmanager
def drop_first_short_tcp(host, dport, max_len=200):
    """drop the first TCP segment of at most max_len bytes (IP length) a host sends to a destination port,
    so it arrives one TCP retransmission timeout (200 ms or more) late; used to force a race"""
    rule = ["OUTPUT", "-p", "tcp", "--dport", str(dport), "--tcp-flags", "PSH", "PSH",
            "-m", "length", "--length", "53:%d" % max_len,
            "-m", "quota", "--quota", str(max_len), "-j", "DROP"]
    in_ns(host, "iptables", "-A", *rule)
    try:
        yield
    finally:
        in_ns(host, "iptables", "-D", *rule, check=False)


NETNS_ETC = "/etc/netns"


def teardown():
    for name in existing_namespaces():
        ip("netns", "del", name, check=False)
    if os.path.isdir(NETNS_ETC):
        for name in os.listdir(NETNS_ETC):
            if name.startswith(PREFIX):
                shutil.rmtree(os.path.join(NETNS_ETC, name), ignore_errors=True)


def _write_name_resolution(host):
    """'ip netns exec' bind mounts /etc/netns/<ns>/{hosts,resolv.conf}: give every namespace all test
    hosts and no DNS server, so name lookups (H323Plus does reverse lookups of the gatekeeper) don't
    wait for DNS timeouts"""
    path = os.path.join(NETNS_ETC, ns(host))
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "hosts"), "w") as f:
        f.write("127.0.0.1\tlocalhost\n")
        for name, addr in HOST_IPS.items():
            f.write("%s\t%s\n" % (addr, name))
        for name, addr in HOST_IPS6.items():
            f.write("%s\t%s-v6\n" % (addr, name))
        for router, (wan, lan, _) in NAT_ROUTERS.items():
            f.write("%s\t%s\n%s.1\t%s-lan\n" % (wan, router, lan, router))
    with open(os.path.join(path, "resolv.conf"), "w") as f:
        f.write("# no DNS in the test network\noptions timeout:1 attempts:1\n")


def _add_ns(host):
    _write_name_resolution(host)
    ip("netns", "add", ns(host))
    in_ns(host, "ip", "link", "set", "lo", "up")
    # keep no TIME-WAIT sockets (IPv4 and IPv6): closed connections of one test would otherwise block
    # the listeners of the next test for 60 seconds (PTLib sets no SO_REUSEADDR on IPv6 listeners)
    in_ns(host, "sysctl", "-qw", "net.ipv4.tcp_max_tw_buckets=0")


def _attach_to_bridge(host, addr):
    port = "v-" + host
    ip("-n", BRIDGE_NS, "link", "add", port, "type", "veth", "peer", "name", "eth0", "netns", ns(host))
    ip("-n", BRIDGE_NS, "link", "set", port, "master", "br0", "up")
    in_ns(host, "ip", "addr", "add", addr + "/24", "dev", "eth0")
    if host in HOST_IPS6 and IPV6_AVAILABLE:
        in_ns(host, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=0")
        in_ns(host, "ip", "-6", "addr", "add", HOST_IPS6[host] + "/64", "dev", "eth0", "nodad")
    in_ns(host, "ip", "link", "set", "eth0", "up")


def setup():
    """Create the whole topology, removing leftovers of an earlier run first."""
    teardown()
    ip("netns", "add", BRIDGE_NS)
    ip("-n", BRIDGE_NS, "link", "set", "lo", "up")
    ip("-n", BRIDGE_NS, "link", "add", "br0", "type", "bridge")
    ip("-n", BRIDGE_NS, "link", "set", "br0", "up")

    for host, addr in PUBLIC_HOSTS.items():
        _add_ns(host)
        _attach_to_bridge(host, addr)

    for router, (wan, lan, priv) in NAT_ROUTERS.items():
        _add_ns(router)
        _attach_to_bridge(router, wan)
        _add_ns(priv)
        ip("-n", ns(router), "link", "add", "lan0", "type", "veth", "peer", "name", "eth0", "netns", ns(priv))
        in_ns(router, "ip", "addr", "add", lan + ".1/24", "dev", "lan0")
        in_ns(router, "ip", "link", "set", "lan0", "up")
        in_ns(router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        in_ns(router, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE")
        in_ns(priv, "ip", "addr", "add", lan + ".10/24", "dev", "eth0")
        in_ns(priv, "ip", "link", "set", "eth0", "up")
        in_ns(priv, "ip", "route", "add", "default", "via", lan + ".1")
