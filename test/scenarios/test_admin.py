"""Gatekeeper administration: config reload, status port commands, call reroute."""

import glob
import re
import time

import pytest

from harness import gnugk, topology
from harness.calls import run_call
from harness.gnugk import StatusSession, pbkdf2_password, status_send
from harness.endpoint import Endpoint


def gnugk_temp_dirs():
    return set(glob.glob("/tmp/gnugk-*"))


def test_reload_during_call(start_gk, workdir):
    """a config reload doesn't disturb an active call, the new config applies and the old private
    temp directory is removed"""
    others = gnugk_temp_dirs()
    gk = start_gk()
    temp_before = gnugk_temp_dirs() - others
    assert len(temp_before) == 1, "expected one private temp directory: %s" % temp_before
    callee = Endpoint(workdir, "pub2", "callee").start(duration=40)
    caller = Endpoint(workdir, "pub1", "caller")
    try:
        assert gk.wait_registered("callee")
        caller.start(call="callee", duration=8)
        time.sleep(3)
        assert gk.number_of_calls() == 1, "call not up before the reload"
        gk.add_config("RasSrv::PermanentEndpoints", {topology.HOST_IPS["pub2"] + ":1730": "addedbyreload;8"})
        reply = gk.reload()
        assert "reload" in reply.lower(), reply
        assert "addedbyreload" in gk.registrations(), "new config not applied"
        assert gk.number_of_calls() == 1, "call lost by the reload"
        caller_result, callee_result = caller.wait(), callee.wait()
    finally:
        caller.kill()
        callee.kill()
    assert caller_result["connected"] and caller_result["endReason"] == "EndedByLocalUser", caller_result
    assert caller_result["durationMs"] >= 7500, "call ended early"
    for side, other in ((caller_result, callee_result), (callee_result, caller_result)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 300, (side, other)
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["cause"] == "16", cdrs
    temp_after = gnugk_temp_dirs() - others
    assert len(temp_after) == 1 and temp_after != temp_before, \
        "the reload should replace the temp directory: before %s after %s" % (temp_before, temp_after)


def disconnect_via_status_port(gk, workdir):
    """call, check PrintCurrentCalls, DisconnectCall it; returns caller and callee results"""
    callee = Endpoint(workdir, "pub2", "callee").start(duration=40)
    caller = Endpoint(workdir, "pub1", "caller")
    try:
        assert gk.wait_registered("callee")
        caller.start(call="callee", duration=20)
        time.sleep(3)
        calls = gk.current_calls()
        assert len(calls) == 1, calls
        number, entry = list(calls.items())[0]
        assert "Dial callee" in entry and "caller:h323_ID" in entry, entry
        assert topology.HOST_IPS["pub1"] in entry and topology.HOST_IPS["pub2"] in entry, entry
        status_send("DisconnectCall %d" % number)
        return caller.wait(), callee.wait()
    finally:
        caller.kill()
        callee.kill()


def test_status_port_print_and_disconnect_call(start_gk, workdir):
    """PrintCurrentCalls shows the call with both parties, DisconnectCall ends it"""
    gk = start_gk()
    caller, callee = disconnect_via_status_port(gk, workdir)
    assert caller["connected"] and caller["durationMs"] < 8000, caller
    assert caller["endReason"] != "EndedByLocalUser" and callee["endReason"] != "EndedByLocalUser"
    assert len(gk.cdrs()) == 1, gk.cdrs()
    assert gk.number_of_calls() == 0


def test_status_port_disconnect_call_cdr(start_gk, workdir):
    """the CDR of a call ended by DisconnectCall says the gatekeeper released it, with normal call clearing
    (not the release source and cause from the endpoints' answering ReleaseCompletes)"""
    gk = start_gk()
    disconnect_via_status_port(gk, workdir)
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["released_by"] == "0" and cdrs[0]["cause"] == "16", cdrs


def test_status_port_unregister_alias(start_gk, workdir):
    """UnregisterAlias: the gatekeeper sends a URQ to the endpoint (H323Plus registers again right away)"""
    gk = start_gk()
    ep = Endpoint(workdir, "pub1", "alice").start(duration=5)
    try:
        assert gk.wait_registered("alice")
        rrqs = gk.trace_count("RRQ Received from")
        status_send("UnregisterAlias alice")
        time.sleep(1)
    finally:
        result = ep.wait()
    assert gk.trace_count("SoftPBX: UnregisterAlias alice") == 1
    ep_trace = open(ep.trace_file, errors="replace").read()
    assert "unregistrationRequest {" in ep_trace.split("Making request: unregistrationRequest")[0], \
        "the endpoint didn't receive the URQ"
    assert gk.trace_count("RRQ Received from") > rrqs, "the endpoint didn't register again"
    assert result["registered"]


def test_status_port_password_login(start_gk, workdir):
    """rule=password: commands only after a login with the right password"""
    gk = start_gk({"GkStatus::Auth": {"rule": "password", "admin": pbkdf2_password("secret"), "DelayReject": "0"}})
    session = StatusSession()
    try:
        session.login("admin", "wrong")
        session.read_until("login: ")	# rejected: asks again
        session.send("admin")
        session.read_until("Password: ")
        session.send("secret")
        reply = session.command("Statistics", "-- Call Statistics --")
        assert "-- Endpoint Statistics --" in reply, reply
    finally:
        session.close()
    assert gk.trace_count("Password digest mismatch for user admin") == 1


# from the tutorial: user gkadmin, password secret, encrypted by addpasswd (not PBKDF2)
TUTORIAL_USER, TUTORIAL_ENTRY = "gkadmin", "QC7VyAo5jEw="


def status_login_accepted(session, user, password):
    """one login attempt with raw bytes as password: True if the session is logged in"""
    session.read_until("login: ")
    session.send(user)
    session.read_until("Password: ")
    session.sock.sendall(password + b"\r\n")
    try:
        session.read_until("login: ", timeout=2)	# rejected: asks again
        return False
    except TimeoutError:
        session.send("Statistics")
        return "-- Endpoint Statistics --" in session.read_until("-- Call Statistics --")


@pytest.mark.parametrize("compare_case", ["1", "0"], ids=["case-sensitive", "case-insensitive"])
def test_status_port_password_user_case(start_gk, workdir, compare_case):
    """status port user names are case sensitive, CompareAliasCase doesn't apply: decrypted with the key
    'GkadMin', the entry for 'gkadmin' gives the one byte 0x85, which must not log in, nor 'GKADMIN' with the
    right password"""
    gk = start_gk({"GkStatus::Auth": {"rule": "password", TUTORIAL_USER: TUTORIAL_ENTRY, "DelayReject": "0"},
                   "Gatekeeper::Main": {"CompareAliasCase": compare_case}})
    session = StatusSession()
    try:
        assert not status_login_accepted(session, "GkadMin", b"\x85")
        assert not status_login_accepted(session, "GKADMIN", b"secret")
        assert status_login_accepted(session, TUTORIAL_USER, b"secret")
    finally:
        session.close()
    assert gk.trace_count("spelling differs from the config") == 2


# user GkAdmin, password secret, encrypted like addpasswd does it for this name (not PBKDF2)
MIXED_CASE_ENTRY = "843gStYyeMs="


@pytest.mark.parametrize("entry", ["traditional", "pbkdf2"])
def test_status_port_mixed_case_user(start_gk, workdir, entry):
    """the right password logs in a user whose name isn't all lower case, for both kinds of entries,
    the same password with the name in lower case doesn't"""
    value = MIXED_CASE_ENTRY if entry == "traditional" else pbkdf2_password("secret")
    gk = start_gk({"GkStatus::Auth": {"rule": "password", "GkAdmin": value, "DelayReject": "0"}})
    session = StatusSession()
    try:
        assert not status_login_accepted(session, "gkadmin", b"secret")
        assert status_login_accepted(session, "GkAdmin", b"secret")
    finally:
        session.close()
    assert gk.trace_count("spelling differs from the config") == 1


def test_status_port_pbkdf2_user_case(start_gk, workdir):
    """status port user names are case sensitive for PBKDF2 entries too: 'ADMIN' with the right password
    doesn't log in to 'admin'"""
    gk = start_gk({"GkStatus::Auth": {"rule": "password", "admin": pbkdf2_password("secret"), "DelayReject": "0"}})
    session = StatusSession()
    try:
        assert not status_login_accepted(session, "ADMIN", b"secret")
        assert status_login_accepted(session, "admin", b"secret")
    finally:
        session.close()
    assert gk.trace_count("spelling differs from the config") == 1


def test_status_port_ip_rule(start_gk, workdir):
    """rule=explicit: only the listed IP may use the status port"""
    start_gk({"GkStatus::Auth": {"rule": "explicit", topology.HOST_IPS["pub1"]: "allow", "default": "forbid"}})
    allowed = StatusSession(host="pub1")
    try:
        assert "Number of Endpoints: 0" in allowed.command("PrintAllRegistrations", "Number of Endpoints: 0")
    finally:
        allowed.close()
    forbidden = StatusSession(host="gk")	# connects from the gatekeeper's own IP
    try:
        with pytest.raises((ConnectionError, OSError)):
            forbidden.command("PrintAllRegistrations", "Number of Endpoints:")
    finally:
        forbidden.close()


def test_status_port_event_filter(start_gk, workdir):
    """status port events, with include and exclude filters"""
    gk = start_gk()
    session = StatusSession()
    try:
        session.send("trace 2")
        session.command("AddIncludeFilter ^RCF", "IncludeFilter added")
        session.command("Filter 1", "Filtering is active")
        session.read_for(0.5)
        Endpoint(workdir, "pub1", "alice").start(duration=1).wait()
        events = session.read_for(1.0)
        assert "RCF|" in events and "alice" in events, events
        assert "URQ|" not in events and "GCF|" not in events, "filter not applied: %s" % events
        session.command("AddExcludeFilter alice", "ExcludeFilter added")
        Endpoint(workdir, "pub1", "alice").start(duration=1).wait()
        events = session.read_for(1.0)
        assert "RCF|" not in events, "exclude filter not applied: %s" % events
    finally:
        session.close()


def test_status_port_statistics_and_endpoint_qos(start_gk, workdir):
    """Statistics counts endpoints, PrintEndpointQoS lists the registered endpoints, the session gets the
    CDR, DCF and UCF events of the call"""
    gk = start_gk()
    callee = Endpoint(workdir, "pub2", "callee").start(duration=30)
    caller = Endpoint(workdir, "pub1", "caller")
    session = StatusSession()
    try:
        assert gk.wait_registered("callee")
        caller.start(call="callee", duration=3)
        time.sleep(2)
        stats = session.command("Statistics", "-- Call Statistics --") + session.read_for(0.3)
        qos = session.command("PrintEndpointQoS", "Number of Endpoints: ") + session.read_for(0.3)
        caller.wait()
        callee.wait()
        events = session.read_for(1.0)
    finally:
        session.close()
        caller.kill()
        callee.kill()
    open(workdir + "/status.txt", "w").write(stats + qos + events)
    assert "Total Endpoints: 2" in stats, stats
    assert "Number of Endpoints: 2" in qos and "caller" in qos and "callee" in qos, qos
    assert "CDR|" in events and events.count("DCF|") == 2 and events.count("UCF|") == 2, events


ACCT_EVENTS = "start,alert,connect,update,stop,register,unregister"


def test_status_acct_events(start_gk, workdir):
    """StatusAcct: register, start, alert, connect, periodic update, stop and unregister events arrive on
    the status port in the right order"""
    gk = start_gk({
        "Gatekeeper::Acct": {"StatusAcct": "required;" + ACCT_EVENTS, "FileAcct": "required;stop"},
        "StatusAcct": {name + "Event": "ACCT|%s|%%{CallId}|%%d" % name
                       for name in ["Start", "Alert", "Connect", "Update", "Stop"]},
        "CallTable": {"AcctUpdateInterval": "10"},	# GnuGk's minimum
    })
    gk.add_config("StatusAcct", {"RegisterEvent": "ACCT|Register|%{endpoint-ip}",
                                 "UnregisterEvent": "ACCT|Unregister|%{endpoint-ip}"})
    gk.reload()
    session = StatusSession()
    try:
        session.read_for(0.5)
        callee = Endpoint(workdir, "pub2", "callee", answer_delay=1).start(duration=30)
        caller = Endpoint(workdir, "pub1", "caller")
        try:
            assert gk.wait_registered("callee")
            caller.start(call="callee", duration=23)
            caller.wait()
            callee.wait()
        finally:
            caller.kill()
            callee.kill()
        events = [line for line in session.read_for(2.0).splitlines() if line.startswith("ACCT|")]
    finally:
        session.close()
    open(workdir + "/acct-events.txt", "w").write("\n".join(events))
    kinds = [e.split("|")[1] for e in events]
    call_kinds = [k for k in kinds if k not in ("Register", "Unregister")]
    assert kinds.count("Register") == 2 and kinds.count("Unregister") == 2, kinds
    assert call_kinds[:3] == ["Start", "Alert", "Connect"] and call_kinds[-1] == "Stop", kinds
    assert call_kinds.count("Update") >= 2, kinds
    stop = [e for e in events if e.startswith("ACCT|Stop|")][0]
    assert int(stop.split("|")[3]) >= 22, stop
    callid = stop.split("|")[2]
    assert all(e.split("|")[2] == callid for e in events if e.split("|")[1] in call_kinds), events


def test_sql_acct(start_gk, workdir):
    """SQLAcct with SQLite: one row per start, alert, update and stop event, the stop has the duration"""
    import sqlite3
    db = workdir + "/acct.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE acct (callid TEXT, event TEXT, duration INTEGER)")
    con.execute("CREATE TABLE eps (ip TEXT, event TEXT)")
    con.commit()
    con.close()
    insert = "INSERT INTO acct VALUES ('%%{CallId}', '%s', %%d)"
    gk = start_gk({
        "Gatekeeper::Acct": {"SQLAcct": "required;start,alert,update,stop,register,unregister",
                             "FileAcct": "required;stop"},
        "SQLAcct": {"Driver": "SQLite", "Database": db,
                    "StartQuery": insert % "start", "AlertQuery": insert % "alert",
                    "UpdateQuery": insert % "update", "StopQuery": insert % "stop",
                    "RegisterQuery": "INSERT INTO eps VALUES ('%{endpoint-ip}', 'register')",
                    "UnregisterQuery": "INSERT INTO eps VALUES ('%{endpoint-ip}', 'unregister')"},
        "CallTable": {"AcctUpdateInterval": "10"},	# GnuGk's minimum
    })
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee", answer_delay=1), duration=23)
    assert caller["connected"]
    con = sqlite3.connect(db)
    rows = con.execute("SELECT callid, event, duration FROM acct ORDER BY rowid").fetchall()
    eps = con.execute("SELECT ip, event FROM eps ORDER BY rowid").fetchall()
    con.close()
    events = [r[1] for r in rows]
    assert events[:2] == ["start", "alert"] and events[-1] == "stop" and events.count("update") >= 2, rows
    assert len({r[0] for r in rows}) == 1, "rows for more than one call id: %s" % rows
    assert rows[-1][2] >= 22, rows
    assert sorted(e for _, e in eps) == ["register", "register", "unregister", "unregister"], eps


@pytest.mark.parametrize("faststart", [
    False,
    pytest.param(True, marks=pytest.mark.xfail(strict=True, reason="with fastStart no media is opened after the "
                 "reroute: the remaining party never gets the new party's capabilities (also in 945303a)")),
], ids=["h245", "faststart"])
def test_reroute_call(start_gk, workdir, faststart):
    """RerouteCall <callid> CALLER third: the caller is rerouted to 'third' and the callee dropped (the
    leg named in the command is the one that stays and gets a new partner; TCS0 pause and reroute,
    30556ce reworked this)"""
    gk = start_gk({"RoutedMode": {"DisableH245Tunneling": "1", "RemoveH235Call": "1"}})
    callee = Endpoint(workdir, "pub2", "callee", faststart=faststart).start(duration=40)
    third = Endpoint(workdir, "pub2", "third", faststart=faststart).start(duration=40)
    caller = Endpoint(workdir, "pub1", "caller", faststart=faststart)
    try:
        assert gk.wait_registered("callee") and gk.wait_registered("third")
        caller.start(call="callee", duration=16)
        time.sleep(4)
        calls = gk.current_calls()
        assert len(calls) == 1, calls
        callid = re.search(r"ACF\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|([0-9a-f-]+)\|", list(calls.values())[0]).group(1)
        status_send("RerouteCall %s CALLER third" % callid, wait=2.0)
        time.sleep(3)
        assert gk.number_of_calls() == 1, "call lost by the reroute"
        caller_result = caller.wait()
        callee_result, third_result = callee.wait(), third.wait()
    finally:
        for ep in (caller, callee, third):
            ep.kill()
    # the caller hangs up at the end (its connect time restarts with the reroute)
    assert caller_result["connected"] and caller_result["endReason"] == "EndedByLocalUser", caller_result
    assert callee_result["connected"] and callee_result["durationMs"] < 9000, "callee not dropped: %s" % callee_result
    assert third_result["connected"], "the call didn't reach 'third': %s" % third_result
    assert third_result["rtpReceived"] > 300 and third_result["rtpSent"] > 300, \
        "no media between caller and third after the reroute: %s" % third_result
    assert gk.trace_count("Reroute aborted") == 0


@pytest.mark.parametrize("h245_ip", [topology.GK_IP, "0.0.0.0"], ids=["gk-ip", "any-ip"])
def test_h245_to_own_status_port(start_gk, workdir, h245_ip):
    """a callee that announces the gatekeeper's own status port as its H.245 address (in the CallProceeding): neither
    the caller nor GnuGk open an H.245 connection to the status port; 0.0.0.0 is the local host, too (GnuGk binds its
    H.245 socket to its home IP, so a connection to 0.0.0.0 goes to the status listener on that IP)"""
    gk = start_gk()
    status = "%s:%d" % (h245_ip, gnugk.STATUS_PORT)
    run_call(gk, Endpoint(workdir, "pub1", "caller", faststart=False, tunneling=False), "callee",
             # ring for a while, so the caller opens its H.245 channel before the Connect brings the real address
             callee=Endpoint(workdir, "pub2", "callee", faststart=False, tunneling=False, h245_address=status,
                             answer_delay=3),
             callee_duration=15)
    # GnuGk puts its own H.245 listener into the CallProceeding for the caller (so the caller isn't sent to the
    # status port) and refuses to connect from there to the callee's address
    assert gk.trace_count("STATUS\tNew connection from %s:" % topology.HOST_IPS["pub1"]) == 0, \
        "the caller was sent to the status port"
    # (the harness itself uses the status port from ephemeral ports, GnuGk's H.245 connections come from 31000-31999)
    assert gk.trace_count("STATUS\tNew connection from %s:31" % topology.GK_IP) == 0, "GnuGk connected to its status port"
    assert gk.trace_count("Refusing H.245 connection to the gatekeeper's own status port") >= 1


@pytest.mark.parametrize("direction", ["olca", "olc"])
@pytest.mark.parametrize("t120_ip,home", [(topology.GK_IP, topology.GK_IP),
                                          ("0.0.0.0", topology.GK_IP + ",127.0.0.1")],
                         ids=["gk-ip", "any-ip-loopback-home"])
def test_t120_to_own_status_port(start_gk, workdir, t120_ip, home, direction):
    """one side signals the gatekeeper's own status port as T.120 separate stack address: the callee in the OLCAck
    for the caller's T.120 channel (olca) or the caller in its OLC (olc). GnuGk puts its T.120 listener into the
    message instead and connects on to the signaled address when the other side connects there: it must refuse to
    connect to its status port, so the status port command sent over the T.120 connection gets no answer.
    0.0.0.0 is the local host, too: when GnuGk also listens on 127.0.0.1 (as without Home=), its (unbound) T.120
    connection to 0.0.0.0 goes there"""
    gk = start_gk({"Gatekeeper::Main": {"Home": home}, "RoutedMode": {"EnableT120": "1"},
                   "Proxy": {"Enable": "1", "T120PortRange": "33000-33099"}})
    status = "%s:%d" % (t120_ip, gnugk.STATUS_PORT)
    if direction == "olca":
        caller = Endpoint(workdir, "pub1", "caller", faststart=False, t120=True, t120_connect=True)
        callee = Endpoint(workdir, "pub2", "callee", faststart=False, t120=True, t120_ack=True, t120_address=status)
    else:
        caller = Endpoint(workdir, "pub1", "caller", faststart=False, t120=True, t120_address=status)
        callee = Endpoint(workdir, "pub2", "callee", faststart=False, t120=True, t120_connect=True)
    caller, callee = run_call(gk, caller, "callee", duration=4, callee=callee)
    connecting = caller if direction == "olca" else callee
    assert caller["connected"] and callee["connected"], caller["endReason"]
    assert callee["t120OlcReceived"], "the T.120 channel didn't reach the callee"
    for ep in ("pub1", "pub2"):
        assert gk.trace_count("STATUS\tNew connection from %s:" % topology.HOST_IPS[ep]) == 0, \
            "%s was sent to the status port" % ep
    assert connecting["t120Connected"], "%s couldn't connect to GnuGk's T.120 listener" % connecting["alias"]
    # GnuGk's T.120 connections come from 33000-33099, the harness uses the status port from ephemeral ports
    for ip in (topology.GK_IP, "127.0.0.1"):
        assert gk.trace_count("STATUS\tNew connection from %s:330" % ip) == 0, "GnuGk connected to its status port"
    assert connecting["t120Reply"] == "", "the status port answered over T.120: %r" % connecting["t120Reply"]
    assert gk.trace_count("Refusing T.120 connection to the gatekeeper's own status port") >= 1
