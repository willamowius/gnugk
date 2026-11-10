"""Operating GnuGk: shutdown with calls up, maintenance mode, the status port commands that unregister
endpoints and end calls, MakeCall, the query commands, status port misuse, the SSH status port, broken
configs and log file handling."""

import os
import re
import signal
import socket
import subprocess
import time

import pytest

from harness import netns, topology
from harness.calls import run_call
from harness.endpoint import Endpoint
from harness.gnugk import STATUS_PORT, StatusSession, status_send

GK = topology.GK_IP
PUB1, PUB2 = topology.HOST_IPS["pub1"], topology.HOST_IPS["pub2"]


def up_call(gk, workdir, caller="caller", callee="callee", caller_host="pub1", callee_host="pub2", duration=40):
    """start a call that stays up (until something ends it), returns (caller, callee) Endpoints"""
    b = Endpoint(workdir, callee_host, callee).start(duration=duration + 10)
    assert gk.wait_registered(callee.split(",")[0])
    a = Endpoint(workdir, caller_host, caller).start(call=callee.split(",")[0], duration=duration)
    deadline = time.time() + 10
    while gk.number_of_calls() == 0 and time.time() < deadline:
        time.sleep(0.2)
    assert gk.number_of_calls() == 1, "the call didn't come up"
    time.sleep(1)
    return a, b


def finish(*endpoints):
    results = []
    try:
        for endpoint in endpoints:
            results.append(endpoint.wait(timeout=60))
    finally:
        for endpoint in endpoints:
            endpoint.kill()
    return results


# ---- shutdown

@pytest.mark.parametrize("how", ["status-port", "sigterm"])
@pytest.mark.parametrize("disconnect", ["1", "0"], ids=["disconnect", "keep"])
def test_shutdown_with_active_call(start_gk, workdir, how, disconnect):
    """GnuGk is stopped (status port Shutdown or SIGTERM) during a routed call: it exits with 0, the call's CDR is
    written; with DisconnectCallsOnShutdown=1 (default) both endpoints get a ReleaseComplete (cause 41, temporary
    failure) and an URQ (the endpoint ends the call on whichever comes first), with 0 the endpoints lose the call anyway (routed mode) but don't get a ReleaseComplete"""
    gk = start_gk({"Gatekeeper::Main": {"DisconnectCallsOnShutdown": disconnect}})
    caller, callee = up_call(gk, workdir)
    if how == "status-port":
        status_send("Shutdown", wait=0.5)
    else:
        gk.signal(signal.SIGTERM)
    code = gk.wait_exit(30)
    caller_result, callee_result = finish(caller, callee)
    assert code == 0, "gnugk exited with %s" % code
    for result in (caller_result, callee_result):
        assert result["connected"] and result["cleared"], result
        assert result["durationMs"] < 20000, "%s kept the call: %s" % (result["alias"], result)
        if disconnect == "1":
            # the ReleaseComplete (cause 41) or the URQ, whichever the endpoint handles first
            assert (result["endReason"] == "EndedByRemoteUser" and result["q931Cause"] == 41) \
                or result["endReason"] == "EndedByGatekeeper", result
        else:
            assert result["endReason"] != "EndedByRemoteUser", result
    assert len(gk.cdrs()) == 1, gk.cdrs()
    urqs = gk.trace_count("unregistrationRequest {")
    if disconnect == "1":
        assert urqs >= 2, "no URQs to the endpoints on shutdown"


# ---- maintenance mode

def test_maintenance_mode(start_gk, workdir):
    """MaintenanceMode: idle endpoints are unregistered, the running call goes on and its endpoints are unregistered
    when it ends, new registrations are refused (GRJ resourceUnavailable); with an alternate IP the reject points
    there; after 'MaintenanceMode OFF' endpoints register and call again"""
    gk = start_gk()
    idle = Endpoint(workdir, "pub3", "idle").start(duration=60)
    assert gk.wait_registered("idle")
    caller, callee = up_call(gk, workdir, duration=8)
    reply = status_send("MaintenanceMode", wait=1.5)
    assert "aintenance" in reply, reply
    time.sleep(1)
    assert "idle" not in gk.registrations(), "the idle endpoint is still registered"
    assert gk.number_of_calls() == 1, "maintenance mode ended the running call"
    refused = Endpoint(workdir, "pub3", "newcomer").start(duration=1, timeout=5).wait()
    assert not refused["registered"], refused
    rejects = gk.ras_events("GRJ") + gk.ras_events("RRJ")
    assert rejects and rejects[0][-1] == "resourceUnavailable", rejects
    caller_result, callee_result = finish(caller, callee)
    assert caller_result["connected"] and caller_result["durationMs"] >= 7500, caller_result
    time.sleep(1)
    assert not ({"caller", "callee"} & gk.registrations()), "endpoints stay registered after their call"
    idle.kill()

    # with an alternate gatekeeper (only while nobody is registered: H323Plus endpoints in a call crash on an
    # URQ that names an alternate gatekeeper)
    status_send("MaintenanceMode OFF", wait=0.5)
    status_send("MaintenanceMode " + topology.HOST_IPS["gk2"], wait=0.5)
    redirected = Endpoint(workdir, "pub3", "redirected").start(duration=1, timeout=5).wait()
    assert not redirected["registered"], redirected
    with open(os.path.join(workdir, "ep-redirected.trace"), errors="replace") as f:
        assert "Added alternate gatekeeper:ip$%s:1719" % topology.HOST_IPS["gk2"] in f.read(), \
            "the reject didn't name the alternate gatekeeper"

    status_send("MaintenanceMode OFF", wait=1.0)
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller", name="caller-after"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", name="callee-after"), duration=2)
    assert caller["connected"] and callee["connected"], caller


# ---- unregistering and disconnecting from the status port

def endpoint_address(gk, alias):
    return next(e["address"] for e in gk.endpoints() if alias in e["aliases"])


def urqs_sent_to(gk, ip):
    """URQs GnuGk sent to ip"""
    count, previous = 0, ""
    with open(gk.trace_file, errors="replace") as f:
        for line in f:
            if line.startswith("unregistrationRequest {") and ("RAS\tSend to " + ip + ":") in previous:
                count += 1
            previous = line
    return count


@pytest.mark.parametrize("command", ["UnregisterIP", "UnregisterAlias", "UnregisterEP", "UnregisterAllEndpoints"])
def test_unregister_commands(start_gk, workdir, command):
    """the unregister commands: the selected endpoint (all for UnregisterAllEndpoints) gets an URQ (H323Plus
    endpoints register again right away), the other endpoint doesn't; an unknown target sends no URQ"""
    gk = start_gk({"Gatekeeper::Main": {"TimeToLive": "600"}})
    alice = Endpoint(workdir, "pub1", "alice,1001").start(duration=8)
    bob = Endpoint(workdir, "pub2", "bob,2001").start(duration=8)
    try:
        assert gk.wait_registered("alice") and gk.wait_registered("bob")
        unknown = {"UnregisterIP": "UnregisterIP 10.99.0.99:1720", "UnregisterAlias": "UnregisterAlias nobody",
                   "UnregisterEP": "UnregisterEP 12345_endp", "UnregisterAllEndpoints": None}[command]
        if unknown:
            gk.send(unknown)
            assert urqs_sent_to(gk, PUB1) == urqs_sent_to(gk, PUB2) == 0, "an unknown target unregistered somebody"
        target = {"UnregisterIP": "UnregisterIP " + endpoint_address(gk, "alice"),
                  "UnregisterAlias": "UnregisterAlias 1001",
                  "UnregisterEP": "UnregisterEP " + gk.endpoint_id("alice"),
                  "UnregisterAllEndpoints": "UnregisterAllEndpoints"}[command]
        gk.send(target)
        time.sleep(1)
        to_alice, to_bob = urqs_sent_to(gk, PUB1), urqs_sent_to(gk, PUB2)
        assert gk.wait_registered("alice"), "alice didn't register again"
    finally:
        alice.kill()
        bob.kill()
    assert to_alice == 1, "URQs to alice: %d" % to_alice
    assert to_bob == (1 if command == "UnregisterAllEndpoints" else 0), "URQs to bob: %d" % to_bob
    assert len([e for e in gk.ras_events("RCF") if "alice" in e[2]]) == 2, "alice didn't register twice"


@pytest.mark.parametrize("command", ["DisconnectIP", "DisconnectAlias", "DisconnectEndpoint", "DisconnectCall",
                                     "DisconnectCallId", "ClearCalls"])
def test_disconnect_commands(start_gk, workdir, command):
    """the disconnect commands end the selected call (both endpoints get a ReleaseComplete) and the CDR is
    written; a target that doesn't exist changes nothing"""
    gk = start_gk()
    caller, callee = up_call(gk, workdir, caller="caller,1001")
    try:
        bogus = {"DisconnectIP": "DisconnectIP 10.99.0.99:1720", "DisconnectAlias": "DisconnectAlias nobody",
                 "DisconnectEndpoint": "DisconnectEndpoint 12345_endp", "DisconnectCall": "DisconnectCall 99",
                 "DisconnectCallId": "DisconnectCallId 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00",
                 "ClearCalls": None}[command]
        if bogus:
            gk.send(bogus)
            assert gk.number_of_calls() == 1, "%s ended the wrong call" % bogus
        (call_number,) = gk.current_calls()
        (call_id,) = gk.call_ids()
        dashed = "-".join(call_id[i:i + 2] for i in range(0, 32, 2))
        target = {"DisconnectIP": "DisconnectIP " + endpoint_address(gk, "caller"),
                  "DisconnectAlias": "DisconnectAlias 1001",
                  "DisconnectEndpoint": "DisconnectEndpoint " + gk.endpoint_id("callee"),
                  "DisconnectCall": "DisconnectCall %d" % call_number,
                  "DisconnectCallId": "DisconnectCallId " + dashed,
                  "ClearCalls": "ClearCalls"}[command]
        gk.send(target)
        assert gk.wait_no_calls(5), "%s didn't end the call" % target
    finally:
        caller_result, callee_result = finish(caller, callee)
    for result in (caller_result, callee_result):
        assert result["connected"] and result["endReason"] == "EndedByRemoteUser", result
        assert result["durationMs"] < 30000, result
    assert len(gk.cdrs()) == 1, gk.cdrs()


# ---- MakeCall

@pytest.mark.parametrize("method", ["FacilityForward", "H.450.2"])
def test_make_call(start_gk, workdir, method):
    """MakeCall alice bob [method]: GnuGk's pseudo endpoint calls alice and then transfers her to bob (the
    default Facility callForwarded, or H.450.2 given in the command); alice and bob end up in a call with each
    other and media"""
    gk = start_gk({"CTI::MakeCall": {"EndpointAlias": "DialOut", "Gatekeeper": GK, "Interface": GK + ":1722"}})
    alice = Endpoint(workdir, "pub1", "alice").start(duration=30, calls=2)
    bob = Endpoint(workdir, "pub2", "bob").start(duration=30)
    try:
        assert gk.wait_registered("alice") and gk.wait_registered("bob")
        # the pseudo endpoint is created (and registers) with the first MakeCall
        status_send("MakeCall alice bob" + ("" if method == "FacilityForward" else " " + method), wait=0.5)
        deadline = time.time() + 15
        while time.time() < deadline and not any("bob" in c for c in gk.current_calls().values()):
            time.sleep(0.3)
        calls = gk.current_calls()
        time.sleep(3)
        status_send("ClearCalls", wait=1.0)
        alice_result, bob_result = finish(alice, bob)
    finally:
        alice.kill()
        bob.kill()
    assert any("alice" in c and "bob" in c for c in calls.values()), "no call between alice and bob: %s" % calls
    assert bob_result["connected"], bob_result
    assert any(c["connected"] and c["rtpReceived"] > 50 for c in alice_result["calls"]), alice_result["calls"]
    assert bob_result["rtpReceived"] > 50, bob_result


# ---- query commands

def test_query_commands(start_gk, workdir):
    """Find / FindVerbose by alias, number and with an alias type, the verbose listings, PrintCallInfo, Who and
    Yell, during a call"""
    gk = start_gk()
    caller, callee = up_call(gk, workdir, caller="caller,1001", callee="callee,2001", duration=8)
    session = StatusSession()
    try:
        (call_id,) = gk.call_ids()
        dashed = "-".join(call_id[i:i + 2] for i in range(0, 32, 2))
        found = gk.send("Find callee")
        found_number = gk.send("Find e164:2001")
        found_wrong_type = gk.send("Find h323:2001")
        verbose = gk.send("FindVerbose 2001")
        registrations = gk.command("PrintAllRegistrationsVerbose", "Number of Endpoints:")
        calls = gk.command("PrintCurrentCallsVerbose", "Number of Calls:")
        info = gk.send("PrintCallInfo " + dashed)
        who = gk.send("Who")
        session.read_for(0.3)
        gk.send("Yell hello from the test")
        yelled = session.read_for(1.0)
    finally:
        session.close()
        finish(caller, callee)
    assert re.search(r"RCF\|%s:\d+\|callee:h323_ID=2001:dialedDigits\|terminal\|\d+_endp" % PUB2, found), found
    assert "callee:h323_ID" in found_number, found_number
    assert "not found" in found_wrong_type, "an E.164 number was found as H.323 ID: %s" % found_wrong_type
    assert "callee" in verbose and "vendor:" in verbose, verbose
    assert registrations.count("RCF|") == 2 and registrations.count("vendor:") == 2, registrations
    assert "Number of Calls: 1" in calls and calls.count("ACF|") == 2 and "# " in calls, calls
    for line in ("CallID: " + dashed, "Status: Connected", "MediaRouting: Proxy", "CallerIP: " + PUB1 + ":",
                 "CalledIP: " + PUB2 + ":", "CalledAlias: callee"):
        assert line in info, "PrintCallInfo has no %r: %s" % (line, info)
    assert len([line for line in who.splitlines() if re.match(r"\s*\d+\t", line)]) >= 2, who
    assert "hello from the test" in yelled, yelled


# ---- status port misuse

def raw_session(timeout=3.0):
    sock = netns.connect("pub1", GK, STATUS_PORT, timeout)
    return sock


def read_all(sock, wait=1.0):
    data = b""
    sock.settimeout(wait)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    except OSError:
        pass
    return data.decode(errors="replace")


@pytest.mark.parametrize("payload", [
    b"xyzzy\r\n",
    b"PrintCurrentCalls " + b"A" * 200000 + b"\r\n",
    b"A" * 1000000,
    bytes(range(256)) * 64 + b"\r\n",
    b"\xff\xfb\x01\xff\xfd\x03" * 1000 + b"\r\n",
    b"Find " + b"%s%n%x" * 100 + b"\r\n",
    b"Yell " + b"\x00" * 100 + b"\r\n",
], ids=["unknown-command", "long-line", "no-newline", "binary", "telnet-negotiation", "format-string", "nul-bytes"])
def test_status_port_garbage(start_gk, workdir, payload):
    """garbage on the status port (unknown commands, very long lines, binary data, telnet negotiation, format
    strings, NUL bytes): GnuGk answers or drops the connection, stays up, other sessions and RAS keep working
    and its memory doesn't grow by the size of the input (file descriptor leaks: see test_robustness.py)"""
    gk = start_gk()
    before = gk.resources()
    sock = raw_session()
    try:
        sock.sendall(payload)
        reply = read_all(sock, 1.0)
    except OSError:
        reply = ""
    finally:
        sock.close()
    time.sleep(0.5)
    assert gk.alive()
    if payload.startswith(b"xyzzy"):
        assert "Unknown command" in reply, reply
    assert "Number of Endpoints: 0" in gk.command("PrintAllRegistrations", "Number of Endpoints:")
    alice = Endpoint(workdir, "pub1", "alice").start(duration=1).wait()
    assert alice["registered"], alice
    after = gk.resources()
    assert after["rss_kb"] - before["rss_kb"] < 20000, (before, after)


def test_status_port_max_clients(start_gk, workdir):
    """MaxStatusClients=3: a 4th connection is refused while 3 are open, after one closes a new one is accepted"""
    gk = start_gk({"Gatekeeper::Main": {"MaxStatusClients": "3"}})
    sessions = []

    def open_session():
        # GnuGk notices closed clients (eg. the probes of start()) a little later, so retry for a while
        deadline = time.time() + 5
        while True:
            session = StatusSession()
            try:
                session.command("Version", "Version:")
                return session
            except (ConnectionError, TimeoutError, OSError):
                session.close()
                if time.time() > deadline:
                    raise
                time.sleep(0.5)

    try:
        for _ in range(3):
            sessions.append(open_session())
        extra = raw_session()
        refused = read_all(extra, 1.5)
        extra.close()
        assert "Version" not in refused, "a 4th client was accepted: %r" % refused
        sessions.pop().close()
        deadline, reply = time.time() + 10, ""
        while time.time() < deadline and "AllRegistrations" not in reply:
            time.sleep(0.5)
            try:
                reply = gk.command("PrintAllRegistrations", "Number of Endpoints:")
            except (ConnectionError, TimeoutError, OSError) as e:
                reply = str(e)
        assert "AllRegistrations" in reply, "no free slot after a client left: %s" % reply
    finally:
        for session in sessions:
            session.close()


def test_status_port_slow_reader(start_gk, workdir):
    """a status client that never reads, with trace 2 while 30 registrations come and go: GnuGk doesn't block on
    it, RAS is answered and another session works"""
    gk = start_gk()
    lazy = raw_session()
    lazy.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    lazy.sendall(b"trace 2\r\n")
    try:
        started = time.time()
        for i in range(30):
            result = Endpoint(workdir, "pub1", "ep%d" % i).start(duration=0, timeout=5).wait()
            assert result["registered"], result
        took = time.time() - started
        assert took < 60, "30 registrations took %d seconds" % took
        assert gk.command("Version", "Version:")
    finally:
        lazy.close()
    assert gk.alive()


# ---- SSH status port

def ssh_run(user, password, command, timeout=15):
    """log into the SSH status port from pub1 with sshpass + ssh, return (exit code, output)"""
    args = ["ip", "netns", "exec", topology.ns("pub1"), "sshpass", "-p", password, "ssh", "-p", str(STATUS_PORT),
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
            "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5", "%s@%s" % (user, GK)]
    if command is not None:
        args.append(command)
    done = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input="")
    return done.returncode, done.stdout + done.stderr


@pytest.fixture
def ssh_tools():
    import shutil
    if not shutil.which("ssh") or not shutil.which("sshpass"):
        pytest.skip("needs ssh and sshpass (apt-get install openssh-client sshpass)")


def ssh_config(workdir, **auth):
    from harness.gnugk import pbkdf2_password
    keyfile = os.path.join(workdir, "ssh_host_rsa_key")
    if not os.path.exists(keyfile):
        subprocess.run(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "", "-f", keyfile], check=True)
    # GnuGk takes RSAKey / DSAKey from [GkStatus::Auth], DSAKey points nowhere so only the test key is used
    section = {"rule": "password", "admin": pbkdf2_password("secret"), "DelayReject": "0",
               "RSAKey": keyfile, "DSAKey": os.path.join(workdir, "no-dsa-key")}
    section.update(auth)
    return {"Gatekeeper::Main": {"SshStatusPort": "1"}, "GkStatus::Auth": section}


def test_ssh_status_port(start_gk, workdir, ssh_tools):
    """SshStatusPort=1: the right password logs in and a command sent as SSH exec gets its reply, a wrong
    password is refused; GnuGk stays up"""
    gk = start_gk(ssh_config(workdir))
    gk.require("ssh")
    code, out = ssh_run("admin", "secret", "Version")
    assert "Gatekeeper(GNU)" in out, (code, out)
    code, out = ssh_run("admin", "wrong", "Version")
    assert code != 0 and "Gatekeeper(GNU)" not in out, (code, out)
    code, out = ssh_run("nobody", "secret", "Version")
    assert code != 0 and "Gatekeeper(GNU)" not in out, (code, out)
    assert gk.alive()


def test_ssh_status_port_ip_rules(start_gk, workdir, ssh_tools):
    """rule=explicit with the client's IP denied: even the right password doesn't get in"""
    gk = start_gk(ssh_config(workdir, rule="explicit", default="allow"), {"GkStatus::Auth": {PUB1: "forbid"}})
    gk.require("ssh")
    code, out = ssh_run("admin", "secret", "Version")
    assert "Gatekeeper(GNU)" not in out, "a denied IP got in: %s" % out
    assert gk.alive()


# ---- broken configs

BROKEN_CONFIGS = {
    "unknown-section": "[NoSuchSection]\nFoo=bar\n",
    "bad-values": "[RoutedMode]\nSignalTimeout=abc\nCpsLimit=-5\n[Proxy]\nRTPPortRange=50000-40000\n"
                  "[Gatekeeper::Main]\nTimeToLive=-1\nTotalBandwidth=xyz\n",
    "bad-regex": "[RasSrv::RewriteE164]\n((=1\n[EP::foo]\nPrefixCapacities=^((:=1\n",
    "binary": "[Gatekeeper::Main]\nName=\x01\x02\xff\nHome=" + GK + "\n" + "\x00" * 100 + "\n[\n=\n",
    "huge-line": "[Gatekeeper::Main]\nName=" + "x" * 200000 + "\n",
}


@pytest.mark.parametrize("broken", list(BROKEN_CONFIGS))
def test_reload_broken_config(start_gk, workdir, broken):
    """garbage added to the config file and a Reload: GnuGk doesn't crash, registrations and calls still work"""
    gk = start_gk()
    with open(gk.config_file, "ab") as f:
        f.write(BROKEN_CONFIGS[broken].encode("latin-1"))
    gk.reload()
    time.sleep(1)
    assert gk.alive()
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"), duration=2)
    assert caller["connected"] and callee["connected"], caller


def test_reload_missing_config_keeps_old_one(start_gk, workdir):
    """the config file is removed and Reload sent: GnuGk keeps running with the config it had (the rewrite rule
    still applies)"""
    gk = start_gk({"RasSrv::RewriteAlias": {"sales": "callee"}})
    os.rename(gk.config_file, gk.config_file + ".gone")
    reply = gk.reload()
    time.sleep(1)
    assert gk.alive(), reply
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "sales",
                              callee=Endpoint(workdir, "pub2", "callee"), duration=2)
    assert caller["connected"] and callee["connected"], "the old config was lost: %s" % caller


def test_start_without_usable_interface(start_gk, workdir):
    """a Home address GnuGk can't use: it refuses to start with a clear error and exit code 1 instead of running
    without listeners"""
    gk = start_gk()
    gk.stop()
    with open(gk.config_file, "a") as f:
        f.write("\n[Gatekeeper::Main]\nHome=192.0.2.77\n")
    with pytest.raises(RuntimeError, match="exited with 1"):
        gk.start()
    gk.stopped = True
    assert "Cannot find any interface" in open(gk.stdout_file, errors="replace").read()


@pytest.mark.parametrize("broken", ["unknown-section", "bad-values", "bad-regex", "huge-line"])
def test_start_with_broken_config(start_gk, workdir, broken):
    """GnuGk starts with garbage in its config and works"""
    gk = start_gk()
    gk.stop()
    with open(gk.config_file, "ab") as f:
        f.write(BROKEN_CONFIGS[broken].encode("latin-1"))
    gk.stopped = False
    gk.start()
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"), duration=2)
    assert caller["connected"] and callee["connected"], caller


# ---- log files

def test_rotate_log(start_gk, workdir):
    """RotateLog during a call: the trace file is renamed with a timestamp and a new one started, tracing goes on,
    the call isn't disturbed"""
    gk = start_gk()
    caller, callee = up_call(gk, workdir, duration=6)
    reply = status_send("RotateLog", wait=1.0)
    caller_result, callee_result = finish(caller, callee)
    assert "Log file rotation succeeded" in reply, reply
    rotated = [name for name in os.listdir(workdir) if re.fullmatch(r"gnugk\.trace\.\d{8}_\d{6}|gnugk\.\d{8}_\d{6}\.trace|gnugk_\d{8}_\d{6}\.trace|gnugk\.trace_\d{8}_\d{6}|gnugk\.\d{8}_\d{6}", name)]
    assert rotated, "no rotated trace file: %s" % os.listdir(workdir)
    assert gk.trace_count("CDR|") == 1, "the new trace file didn't get the rest of the call"
    assert caller_result["connected"] and caller_result["endReason"] == "EndedByLocalUser", caller_result


def test_setlog_and_trace_level(start_gk, workdir):
    """setlog moves the trace to another file, 'debug trc' changes the trace level on the fly; a call works while
    both happen and its CDR line ends up in the new file"""
    gk = start_gk()
    newlog = os.path.join(workdir, "moved.trace")
    caller, callee = up_call(gk, workdir, duration=6)
    reply = status_send("setlog " + newlog, wait=0.5)
    level = status_send("debug trc 1", wait=0.5)
    caller_result, callee_result = finish(caller, callee)
    assert "Logging to the file" in reply, reply
    assert "1" in level, level
    assert os.path.exists(newlog)
    moved = open(newlog, errors="replace").read()
    assert "CDR|" in moved, "the CDR didn't go to the new log"
    assert "RAS\tRead from" not in moved, "trace level 1 still logs level 2 lines"
    bad = status_send("setlog /nonexistent-dir/x.trace", wait=0.5)
    assert "Failed" in bad, bad
    assert gk.alive()
    assert caller_result["connected"], caller_result
