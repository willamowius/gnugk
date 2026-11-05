"""Run GnuGk inside the gk namespace and talk to its status port."""

import copy
import os
import re
import subprocess
import time

from . import netns, topology
from .paths import ADDPASSWD, GNUGK

STATUS_PORT = 7000
MD5_KEY = "11"

# CDR fields written by FileAcct, see parse_cdrs()
CDR_FIELDS = ["callid", "duration", "cause", "released_by", "caller_ip", "callee_ip", "src_info", "dest_info",
              "dialed_number", "called_station", "calling_station", "caller_epid", "callee_epid",
              "client_auth_id"]

BASE_CONFIG = {
    "Gatekeeper::Main": {
        "Name": "GnuGkTest",
        "Home": topology.GK_IP,
        "TimeToLive": "600",
        "StatusPort": str(STATUS_PORT),
    },
    "RoutedMode": {
        "GKRouted": "1",
        "H245Routed": "1",
        "CallSignalPort": "1720",
        "AcceptUnregisteredCalls": "0",
        "SupportNATedEndpoints": "1",
        "DropCallsByReleaseComplete": "1",
        "Q931PortRange": "30000-30999",
        "H245PortRange": "31000-31999",
    },
    "Proxy": {
        "Enable": "1",
        # without InternalNetwork GnuGk treats its own networks as internal and doesn't proxy calls inside
        # them (all public test hosts share the gatekeeper's network), so name an unused network
        "InternalNetwork": "192.0.2.0/24",
        "RTPPortRange": "40000-41999",
        "T120PortRange": "42000-42999",
    },
    "GkStatus::Auth": {
        "rule": "allow",
    },
    "Gatekeeper::Acct": {
        "FileAcct": "required;stop",
    },
    "FileAcct": {
        "StandardCDRFormat": "0",
        "CDRString": "%{CallId}|%d|%c|%r|%{caller-ip}|%{callee-ip}|%{src-info}|%{dest-info}"
                     "|%{Dialed-Number}|%{Called-Station-Id}|%{Calling-Station-Id}|%{caller-epid}|%{callee-epid}|%{client-auth-id}",
    },
}


def merge_config(*overrides):
    """BASE_CONFIG updated with the given {section: {key: value}} dicts, a value of None deletes the key,
    a section of None deletes the section."""
    cfg = copy.deepcopy(BASE_CONFIG)
    for override in overrides:
        for section, keys in override.items():
            if keys is None:
                cfg.pop(section, None)
                continue
            target = cfg.setdefault(section, {})
            for key, value in keys.items():
                if value is None:
                    target.pop(key, None)
                else:
                    target[key] = value
    return cfg


def h46018_config():
    return {"RoutedMode": {"EnableH46018": "1"}}


# only the messages an H323Plus endpoint puts its MD5 (cryptoEPPwdHash) token into:
# H235AuthSimpleMD5::IsSecuredPDU() secures RRQ, URQ, ARQ, BRQ, DRQ and IRR (SimplePasswordAuth can't
# check IRR). The Q.931 Setup only carries H.235.1 tokens, no MD5, and a bare "required" would also
# check every other Q.931 message (CallProceeding, Alerting, ...), so no Q.931 message is listed.
MD5_CHECKED_MESSAGES = "RRQ,URQ,ARQ,BRQ,DRQ"


# H.235.1 (Procedure I) tokens are in all RAS messages and in the Q.931 Setup
H2351_SETUP_CHECKED_MESSAGES = "RRQ,URQ,ARQ,BRQ,DRQ,Setup"


def h2351_setup_config():
    """H.235.1, checking the RAS messages and the Setup"""
    return {
        "Gatekeeper::Auth": {"SimplePasswordAuth": "required;" + H2351_SETUP_CHECKED_MESSAGES},
        "SimplePasswordAuth": {"KeyFilled": MD5_KEY},
    }


def h2351_all_config():
    """H.235.1, checking all messages SimplePasswordAuth supports (RAS and every Q.931 message).
    With the default [H235] FullQ931Checking=0 only the Setup must carry a token."""
    return {
        "Gatekeeper::Auth": {"SimplePasswordAuth": "required"},
        "SimplePasswordAuth": {"KeyFilled": MD5_KEY},
    }


def md5_config():
    return {
        "Gatekeeper::Auth": {"SimplePasswordAuth": "required;" + MD5_CHECKED_MESSAGES},
        "SimplePasswordAuth": {"KeyFilled": MD5_KEY},
    }


def status_command(cmd, end_marker, timeout=5.0, host="gk"):
    """Send a command on a fresh status port connection to the GnuGk on host and return the reply up to and
    including the line starting with end_marker (the port also sends asynchronous event lines, so this
    skips those)."""
    sock = netns.connect(host, topology.HOST_IPS[host], STATUS_PORT, timeout)
    try:
        sock.sendall(cmd.encode() + b"\r\n")
        data = b""
        deadline = time.time() + timeout
        while True:
            text = data.decode(errors="replace")
            pos = text.find("\n" + end_marker)
            if pos >= 0 and text.find("\n;", pos) >= 0:
                return text
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("no reply to %r from the status port: %r" % (cmd, text))
            sock.settimeout(remaining)
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("status port closed: %r" % text)
            data += chunk
    finally:
        sock.close()


def status_send(cmd, wait=1.0, host="gk"):
    """Send a command on a fresh status port connection to the GnuGk on host and return whatever arrives
    within wait seconds"""
    sock = netns.connect(host, topology.HOST_IPS[host], STATUS_PORT)
    try:
        sock.sendall(cmd.encode() + b"\r\n")
        data = b""
        deadline = time.time() + wait
        while time.time() < deadline:
            sock.settimeout(max(deadline - time.time(), 0.01))
            try:
                chunk = sock.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        return data.decode(errors="replace")
    finally:
        sock.close()


class StatusSession:
    """A status port connection that stays open: login, commands, asynchronous events"""

    def __init__(self, host="gk", timeout=5.0, gk="gk"):
        """connect from host (namespace) to the status port of the GnuGk on gk"""
        self.sock = netns.connect(host, topology.HOST_IPS[gk], STATUS_PORT, timeout)
        self.buffer = ""

    def read_until(self, text, timeout=5.0):
        """read until text arrives, return everything up to it (TimeoutError / ConnectionError otherwise)"""
        deadline = time.time() + timeout
        while text not in self.buffer:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("no %r from the status port, got %r" % (text, self.buffer))
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("status port closed, got %r" % self.buffer)
            # drop telnet negotiation (IAC sequences) GnuGk sends around the password prompt
            self.buffer += re.sub(rb"\xff[\xfb-\xfe].", b"", chunk).decode(errors="replace")
        pos = self.buffer.index(text) + len(text)
        result, self.buffer = self.buffer[:pos], self.buffer[pos:]
        return result

    def read_for(self, seconds):
        """everything that arrives within seconds"""
        try:
            return self.read_until("\x00never\x00", seconds)
        except TimeoutError:
            result, self.buffer = self.buffer, ""
            return result

    def send(self, line):
        self.sock.sendall(line.encode() + b"\r\n")

    def login(self, user, password):
        self.read_until("login: ")
        self.send(user)
        self.read_until("Password: ")
        self.send(password)

    def command(self, cmd, end_marker, timeout=5.0):
        self.send(cmd)
        return self.read_until(end_marker, timeout)

    def close(self):
        self.sock.close()


def pbkdf2_password(password, salt="0123456789abcdef"):
    """[GkStatus::Auth] user entry for a password, like addpasswd makes it (PBKDF2-SHA512)"""
    import hashlib
    digest = hashlib.pbkdf2_hmac("sha512", password.encode(), salt.encode(), 65536, 32).hex()
    return "PBKDF2:%s-%s" % (salt, digest)


class GnuGk:
    def __init__(self, workdir, config, users=None, host="gk", name="gnugk", trace=None):
        """config: {section: {key: value}}, users: {alias: password} for SimplePasswordAuth,
        host: the namespace to run in, name: for the files (a 2nd gatekeeper needs another name),
        trace: at least this trace level (the default is GKTEST_GK_TRACE or 5)"""
        self.workdir = workdir
        self.name = name
        self.trace_level = max(int(os.environ.get("GKTEST_GK_TRACE", "5")), trace or 0)
        self.host = host
        self.ip = topology.HOST_IPS[host]
        self.config_file = os.path.join(workdir, name + ".ini")
        self.trace_file = os.path.join(workdir, name + ".trace")
        self.cdr_file = os.path.join(workdir, "cdr.txt" if name == "gnugk" else name + "-cdr.txt")
        self.stdout_file = os.path.join(workdir, name + ".stdout")
        config = merge_config(config, {"FileAcct": {"DetailFile": self.cdr_file}})
        if config["Gatekeeper::Main"].get("Home") == topology.GK_IP:
            config["Gatekeeper::Main"]["Home"] = self.ip
        with open(self.config_file, "w") as f:
            for section, keys in config.items():
                f.write("[%s]\n" % section)
                for key, value in keys.items():
                    f.write("%s=%s\n" % (key, value))
                f.write("\n")
        for alias, password in (users or {}).items():
            subprocess.run([ADDPASSWD, self.config_file, "SimplePasswordAuth", alias, password],
                           check=True, capture_output=True)
        self.proc = None

    def ports_in_use(self):
        """the TCP/UDP ports GnuGk needs on its host that something already listens on"""
        wanted = {1719, 1720, STATUS_PORT}
        busy = []
        for line in topology.sockets(self.host).splitlines()[1:]:
            fields = line.split()
            if len(fields) < 5 or fields[1] not in ("UNCONN", "LISTEN"):
                continue
            port = fields[4].rsplit(":", 1)[-1]
            if port.isdigit() and int(port) in wanted:
                busy.append(line.strip())
        return busy

    def start(self, timeout=10.0):
        # GnuGk would start without its listeners if an earlier test still held the ports
        deadline = time.time() + 5
        while self.ports_in_use() and time.time() < deadline:
            time.sleep(0.2)
        busy = self.ports_in_use()
        if busy:
            raise RuntimeError("ports GnuGk needs (RAS, Q.931, status port) are still in use on %s:\n%s"
                               % (self.host, "\n".join(busy)))
        self._stdout = open(self.stdout_file, "w")
        self.proc = subprocess.Popen(
            ["ip", "netns", "exec", topology.ns(self.host), GNUGK,
             "-c", self.config_file, "-" + "t" * self.trace_level, "-o", self.trace_file],
            stdout=self._stdout, stderr=subprocess.STDOUT)
        deadline = time.time() + timeout
        while True:
            if self.proc.poll() is not None:
                raise RuntimeError("gnugk exited with %d, see %s" % (self.proc.returncode, self.stdout_file))
            try:
                netns.connect(self.host, self.ip, STATUS_PORT).close()
                return self
            except OSError:
                if time.time() > deadline:
                    self.stop()	# don't leave it running, it would hold the ports for the next tests
                    raise RuntimeError("gnugk didn't open its status port within %d seconds, see %s"
                                       % (timeout, self.trace_file))
                time.sleep(0.2)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.proc is not None:
            self._stdout.close()
        return self.proc.returncode if self.proc else None

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def add_config(self, section, keys):
        """add/change config entries in the config file (eg. before a Reload)"""
        with open(self.config_file, "a") as f:
            f.write("\n[%s]\n" % section)
            for key, value in keys.items():
                f.write("%s=%s\n" % (key, value))

    def reload(self):
        return status_send("Reload", wait=2.0, host=self.host)

    def resources(self):
        """{'rss_kb': resident memory, 'fds': open file descriptors, 'threads': thread count} of GnuGk"""
        pid = self.proc.pid	# 'ip netns exec' execs gnugk, so this is gnugk itself
        status = open("/proc/%d/status" % pid).read()
        rss = int(re.search(r"VmRSS:\s+(\d+)", status).group(1))
        threads = int(re.search(r"Threads:\s+(\d+)", status).group(1))
        return {"rss_kb": rss, "fds": len(os.listdir("/proc/%d/fd" % pid)), "threads": threads}

    def features(self):
        """Compile time features from the version line, eg. {'h46018': True, 'ipv6': True, ...}"""
        with open(self.trace_file, errors="replace") as f:
            for line in f:
                match = re.search(r"Ext\(([^)]*)\)", line)
                if match:
                    return {k: v == "1" for k, v in (item.split("=") for item in match.group(1).split(","))}
        return {}

    def require(self, *features):
        missing = [f for f in features if not self.features().get(f)]
        if missing:
            raise RuntimeError("gnugk was built without %s, see test/build-deps.sh" % ", ".join(missing))

    def trace_count(self, text):
        """how many lines of the GnuGk trace contain text"""
        with open(self.trace_file, errors="replace") as f:
            return sum(1 for line in f if text in line)

    def ras_events(self, kind):
        """RAS events of one kind (eg. 'RRJ') GnuGk logged, as lists of the '|' separated fields"""
        events = []
        with open(self.trace_file, errors="replace") as f:
            for line in f:
                pos = line.find("\t" + kind + "|")
                if pos >= 0:
                    events.append(line[pos + 1:].rstrip().rstrip(";").split("|"))
        return events

    def rejected_registration(self, alias):
        """the reject reason GnuGk sent for alias, None if it sent no RRJ"""
        for event in self.ras_events("RRJ"):
            if any(field.split(":")[0] == alias for field in event[2:3]):
                return event[-1]
        return None

    # status port helpers

    def registrations(self):
        """Registered aliases, as listed by PrintAllRegistrations."""
        reply = status_command("PrintAllRegistrations", "Number of Endpoints:", host=self.host)
        aliases = set()
        for line in reply.splitlines():
            if line.startswith("RCF|"):
                # RCF|ip:port|alias:type=alias:type|terminalType|epid
                fields = line.split("|")
                if len(fields) > 2:
                    for alias in re.split(r"[=,]", fields[2]):
                        aliases.add(alias.split(":")[0].strip())
        return aliases

    def wait_registered(self, alias, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if alias in self.registrations():
                return True
            time.sleep(0.2)
        return False

    def current_calls(self):
        """PrintCurrentCalls: {call number: text of the call's entry}"""
        reply = status_command("PrintCurrentCalls", "Number of Calls:", host=self.host)
        calls = {}
        for entry in re.split(r"(?=Call No\. )", reply):
            match = re.match(r"Call No\. (\d+) ", entry)
            if match:
                calls[int(match.group(1))] = entry
        return calls

    def number_of_calls(self):
        reply = status_command("PrintCurrentCalls", "Number of Calls:", host=self.host)
        for line in reply.splitlines():
            if line.startswith("Number of Calls:"):
                return int(line.split()[3])
        raise ValueError("unexpected PrintCurrentCalls reply: " + reply)

    def cdrs(self):
        if not os.path.exists(self.cdr_file):
            return []
        cdrs = []
        with open(self.cdr_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    cdrs.append(dict(zip(CDR_FIELDS, line.split("|"))))
        return cdrs
