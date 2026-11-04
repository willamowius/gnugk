"""Run gktestep (test/endpoint) inside a host namespace."""

import json
import os
import signal
import subprocess

from . import topology
from .paths import ENDPOINT


class Endpoint:
    def __init__(self, workdir, host, alias, password=None, h46018=False, faststart=True, h2351=False, full_q931=False,
                 md5_unsigned=None, reject=None, hangup_after=None, tunneling=True, name=None, no_gk=False,
                 answer_delay=None, instance=0, bandwidth=None, brq=None, add_aliases=None,
                 gateway=False, ipv6=False, gk="gk", h46019m=False):
        """password: register with MD5 tokens, or H.235.1 tokens with h2351 (also in the call Setup,
        or in all Q.931 messages with full_q931). md5_unsigned: RAS messages to send without MD5 token,
        eg. ["URQ", "DRQ"]. reject: refuse incoming calls, "busy" or "denied".
        hangup_after: callee hangs up an answered call after this many seconds.
        tunneling: False to use a separate H.245 channel.
        name: for the result files (default: the first alias), when several endpoints use the same alias.
        no_gk: don't register, call the address given as call target directly.
        answer_delay: callee rings this many seconds before answering.
        instance: to run several endpoints on one host, shifts the signaling, RAS and RTP ports.
        bandwidth: to ask for in ARQs, brq: caller sends a BRQ for this bandwidth (units of 100 bit/s).
        add_aliases: aliases to add with an additive registration (in the next keep-alive RRQ).
        gateway: register as gateway (prefixes come from the GnuGk config, eg. [RasSrv::GWPrefixes]).
        ipv6: use the host's and the gatekeeper's IPv6 addresses.
        gk: the host of the gatekeeper to register with
        h46019m: with h46018, use H.460.19 RTP multiplexing
        """
        self.workdir = workdir
        self.host = host
        self.alias = alias
        self.password = password
        self.h46018 = h46018
        self.faststart = faststart
        self.h2351 = h2351
        self.full_q931 = full_q931
        self.md5_unsigned = md5_unsigned or []
        self.reject = reject
        self.hangup_after = hangup_after
        self.tunneling = tunneling
        self.answer_delay = answer_delay
        self.instance = instance
        self.bandwidth = bandwidth
        self.brq = brq
        self.add_aliases = add_aliases
        self.gateway = gateway
        self.ipv6 = ipv6
        self.gk = gk
        self.h46019m = h46019m
        self.listen_port = 1720 + 10 * instance
        name = name or alias.split(",")[0]
        self.result_file = os.path.join(workdir, "ep-%s.json" % name)
        self.trace_file = os.path.join(workdir, "ep-%s.trace" % name)
        self.stdout_file = os.path.join(workdir, "ep-%s.stdout" % name)
        self.proc = None
        self.no_gk = no_gk

    def start(self, call=None, duration=5, timeout=10, calls=1):
        """Register and either call the given alias or wait duration seconds for a call."""
        if os.path.exists(self.result_file):
            os.remove(self.result_file)
        if self.ipv6:
            addr, gk_addr = "[%s]" % topology.HOST_IPS6[self.host], "[%s]" % topology.GK_IP6
        else:
            addr, gk_addr = topology.HOST_IPS[self.host], topology.HOST_IPS[self.gk]
        args = ["ip", "netns", "exec", topology.ns(self.host), ENDPOINT,
                "--alias", self.alias,
                "--listen", "%s:%d" % (addr, self.listen_port), "--result", self.result_file,
                "--duration", str(duration), "--timeout", str(timeout),
                "--trace", os.environ.get("GKTEST_EP_TRACE", "5"), "--log", self.trace_file]
        args += ["--no-gk"] if self.no_gk else ["--gk", gk_addr]
        base = 5000 + 100 * self.instance
        args += ["--ras-port", str(1719 + 10 * self.instance), "--rtp-ports", "%d-%d" % (base, base + 99)]
        if self.password is not None:
            args += ["--password", self.password]
        if self.h46018:
            args.append("--h46018")
        if self.h46019m:
            args.append("--h46019m")
        if not self.faststart:
            args.append("--no-faststart")
        if self.h2351:
            args.append("--h2351")
        if self.full_q931:
            args.append("--full-q931")
        if self.gateway:
            args.append("--gateway")
        if self.add_aliases:
            args += ["--add-alias", ",".join(self.add_aliases)]
        if self.bandwidth is not None:
            args += ["--bandwidth", str(self.bandwidth)]
        if self.brq is not None:
            args += ["--brq", str(self.brq)]
        if self.answer_delay is not None:
            args += ["--answer-delay", str(self.answer_delay)]
        if not self.tunneling:
            args.append("--no-tunneling")
        if self.hangup_after is not None:
            args += ["--hangup-after", str(self.hangup_after)]
        if self.reject:
            args += ["--reject", self.reject]
        if self.md5_unsigned:
            args += ["--md5-unsigned", ",".join(self.md5_unsigned)]
        if call:
            args += ["--call", call]
        if calls != 1:
            args += ["--calls", str(calls)]
        self._stdout = open(self.stdout_file, "w")
        self.proc = subprocess.Popen(args, stdout=self._stdout, stderr=subprocess.STDOUT)
        return self

    def wait(self, timeout=60):
        """Wait for the endpoint to finish and return its JSON result."""
        try:
            self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            raise
        finally:
            self._stdout.close()
        if not os.path.exists(self.result_file):
            raise RuntimeError("%s wrote no result (exit code %d), see %s"
                               % (self.alias, self.proc.returncode, self.stdout_file))
        with open(self.result_file) as f:
            return json.load(f)

    def pause(self):
        """freeze the endpoint (SIGSTOP), it stops sending anything"""
        self.proc.send_signal(signal.SIGSTOP)

    def resume(self):
        self.proc.send_signal(signal.SIGCONT)

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
