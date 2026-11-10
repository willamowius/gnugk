"""External decision makers: the HTTP modules (HttpPasswordAuth, the http routing policy, HttpAcct) against an HTTP
server on pub3, and the Lua modules (LuaAuth, the lua routing policy, LuaAcct), also when the server is slow or
down and when a script fails."""

import os
import time

import pytest

from harness import topology
from harness.calls import run_call
from harness.endpoint import Endpoint
from harness.http import HttpServer

PUB2 = topology.HOST_IPS["pub2"]


def dial(gk, workdir, dialed, name, duration=1, **caller_args):
    return run_call(gk, Endpoint(workdir, "pub1", "caller", name="caller-" + name, **caller_args), dialed,
                    duration=duration)[0]


def arj_count(gk):
    return len(gk.ras_events("ARJ"))


# ---- HTTP

PASSWORDS = {"alice": "secretA", "bob": "secretB"}


def password_responder(request):
    alias = (request["query"].get("user") or [""])[0]
    if alias in PASSWORDS:
        return 200, PASSWORDS[alias]
    return 404, "error: unknown user"


def http_password_config(url, **extra):
    section = {"URL": url + "/passwords?user=%u&msg=%{message}", "Method": "GET", "ErrorRegex": "error",
               "PasswordTimeout": "0"}
    section.update(extra)
    return {"Gatekeeper::Auth": {"HttpPasswordAuth": "required;RRQ,ARQ"}, "HttpPasswordAuth": section}


def test_http_password_auth(start_gk, workdir):
    """HttpPasswordAuth: GnuGk fetches the password for the alias (GET with %u and %{message}) and checks the
    endpoint's MD5 token with it: the right password registers and calls, a wrong one and an unknown alias (the
    server answers 404 / 'error') are rejected"""
    with HttpServer(responder=password_responder) as http:
        gk = start_gk(http_password_config(http.url))
        good = Endpoint(workdir, "pub1", "alice", password="secretA").start(duration=1).wait()
        wrong = Endpoint(workdir, "pub1", "bob", password="nope").start(duration=1, timeout=4).wait()
        unknown = Endpoint(workdir, "pub1", "mallory", password="x").start(duration=1, timeout=4).wait()
        caller, callee = run_call(gk, Endpoint(workdir, "pub1", "alice", password="secretA", name="alice-calls"),
                                  "bob", callee=Endpoint(workdir, "pub2", "bob", password="secretB"), duration=1)
        requests = list(http.requests)
    assert good["registered"], good
    assert not wrong["registered"] and wrong["registrationRejected"], wrong
    assert not unknown["registered"], unknown
    assert caller["connected"] and callee["connected"], caller
    asked = [(r["query"]["user"][0], r["query"]["msg"][0]) for r in requests]
    # the ARQ is checked with the password GnuGk already has for the registered endpoint
    assert ("alice", "RRQ") in asked and ("mallory", "RRQ") in asked, asked


@pytest.mark.parametrize("server", ["down", "slow"])
def test_http_password_auth_server_unavailable(start_gk, workdir, server):
    """the password server is down (nothing listens) or answers only after 20 seconds: the registration is
    refused or times out, GnuGk stays up and an endpoint that needs no HTTP lookup (other auth rule) is
    served in the meantime"""
    config = http_password_config("http://%s:8080" % topology.HOST_IPS["pub3"])
    config["Gatekeeper::Auth"] = {"HttpPasswordAuth": "required;RRQ", "default": "allow"}
    http = HttpServer(responder=password_responder, delay=20).start() if server == "slow" else None
    try:
        gk = start_gk(config)
        alice = Endpoint(workdir, "pub1", "alice", password="secretA").start(duration=1, timeout=6)
        time.sleep(1)
        started = time.time()
        assert "Version" in gk.command("Version", "Version:"), "the status port hangs"
        status_time = time.time() - started
        alice_result = alice.wait(timeout=60)
    finally:
        if http:
            http.stop()
    assert not alice_result["registered"], alice_result
    assert status_time < 3, "the status port waited %.1f s for the HTTP server" % status_time
    assert gk.alive()


def route_responder(table):
    def respond(request):
        called = (request["query"].get("called") or [""])[0]
        return 200, table.get(called, "")
    return respond


def test_http_routing(start_gk, workdir):
    """http routing policy: the server's answer is a new alias (sales -> bob), an IP (support -> pub2, an
    unregistered endpoint) or REJECT; an empty answer lets the next policy (internal) route the call"""
    table = {"sales": "bob", "support": PUB2, "blocked": "REJECT"}
    with HttpServer(responder=route_responder(table)) as http:
        gk = start_gk({"RoutingPolicy": {"default": "http,internal"},
                       "Routing::Http": {"URL": http.url + "/route?called=%c&from=%s&msg=%m", "Method": "GET"}})
        bob = Endpoint(workdir, "pub2", "bob").start(duration=40, calls=2)
        support = Endpoint(workdir, "pub2", "support", no_gk=True, listen_port=1720).start(duration=40)
        try:
            assert gk.wait_registered("bob")
            sales = dial(gk, workdir, "sales", "sales")
            ip = dial(gk, workdir, "support", "support")
            blocked = dial(gk, workdir, "blocked", "blocked")
            direct = dial(gk, workdir, "bob", "direct")
            bob_result, support_result = bob.wait(), support.wait()
        finally:
            bob.kill()
            support.kill()
        requests = list(http.requests)
    assert sales["connected"] and ip["connected"] and direct["connected"], (sales, ip, direct)
    assert not blocked["connected"], blocked
    assert bob_result["callsConnected"] == 2 and support_result["connected"], (bob_result, support_result)
    assert requests and requests[0]["query"]["msg"] == ["ARQ"] and requests[0]["query"]["from"][0].startswith(
        topology.HOST_IPS["pub1"]), requests[0]


def test_http_routing_json(start_gk, workdir):
    """JSONResponse=1: {"destination": alias}, {"reject": true} and, as documented for failover, an array of routes
    with IP destinations (the first one, gw0, refuses the call with a failover cause, the second one, bob, gets it)"""
    answers = {
        "sales": '{"destination": "bob"}',
        "blocked": '{"reject": true, "reject-reason": 2}',
        # "both" is filled in once the endpoints are registered and their addresses are known
    }
    with HttpServer(responder=route_responder(answers)) as http:
        gk = start_gk({"RoutingPolicy": {"default": "http,internal"}, "RoutedMode": {"ActivateFailover": "1"},
                       "Routing::Http": {"URL": http.url + "/route?called=%c", "Method": "GET", "JSONResponse": "1"}})
        if not gk.features().get("json"):
            pytest.skip("GnuGk was built without JSON support (nlohmann/json.hpp, apt-get install nlohmann-json3-dev)")
        bob = Endpoint(workdir, "pub2", "bob").start(duration=40, calls=2)
        gw0 = Endpoint(workdir, "pub2", "gw0", reject="denied").start(duration=40)
        try:
            assert gk.wait_registered("bob") and gk.wait_registered("gw0")
            addresses = {e["aliases"][0]: e["address"] for e in gk.endpoints()}
            answers["both"] = '[{"destination": "%s"}, {"destination": "%s"}]' % (addresses["gw0"], addresses["bob"])
            sales = dial(gk, workdir, "sales", "sales")
            blocked = dial(gk, workdir, "blocked", "blocked")
            both = dial(gk, workdir, "both", "both")
            bob_result, gw0_result = bob.wait(), gw0.wait()
        finally:
            bob.kill()
            gw0.kill()
    assert sales["connected"], sales
    assert not blocked["connected"], blocked
    assert gw0_result["callAttempted"] and not gw0_result["connected"], gw0_result
    assert both["connected"] and bob_result["callsConnected"] == 2, (both, bob_result)


def test_http_routing_server_down(start_gk, workdir):
    """the routing server is down: the http policy doesn't route and the next policy (internal) does"""
    gk = start_gk({"RoutingPolicy": {"default": "http,internal"},
                   "Routing::Http": {"URL": "http://%s:8080/route?called=%%c" % topology.HOST_IPS["pub3"],
                                     "Method": "GET"}})
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "bob",
                              callee=Endpoint(workdir, "pub2", "bob"), duration=1)
    assert caller["connected"] and callee["connected"], caller


def test_http_accounting(start_gk, workdir):
    """HttpAcct with start, connect and stop events (POST with a body): the server gets one request per event
    in order, with the call ID, the caller and the duration"""
    with HttpServer() as http:
        acct = {"Method": "POST", "ContentType": "application/x-www-form-urlencoded",
                "StartURL": http.url + "/start", "StartBody": "callid=%{CallId}&caller=%{Calling-Station-Id}",
                "ConnectURL": http.url + "/connect", "ConnectBody": "callid=%{CallId}",
                "StopURL": http.url + "/stop", "StopBody": "callid=%{CallId}&duration=%d&cause=%c"}
        gk = start_gk({"Gatekeeper::Acct": {"HttpAcct": "required;start,connect,stop", "FileAcct": "required;stop"},
                       "HttpAcct": acct})
        caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller,1001"), "callee",
                                  callee=Endpoint(workdir, "pub2", "callee"), duration=3)
        time.sleep(1)
        requests = list(http.requests)
    assert caller["connected"], caller
    assert [r["path"] for r in requests] == ["/start", "/connect", "/stop"], [r["path"] for r in requests]
    from urllib.parse import parse_qs
    bodies = [parse_qs(r["body"]) for r in requests]
    call_ids = {b["callid"][0] for b in bodies}
    assert len(call_ids) == 1 and call_ids.pop().replace(" ", "") == gk.cdrs()[0]["callid"].replace(" ", ""), bodies
    assert bodies[0]["caller"] == ["1001"], bodies[0]
    assert int(bodies[2]["duration"][0]) >= 2 and bodies[2]["cause"] == ["16"], bodies[2]


# ---- Lua

def lua_or_skip(gk):
    gk.require("lua")


def test_lua_auth(start_gk, workdir):
    """LuaAuth: the registration script refuses aliases starting with 'bad', the call script refuses calls to
    'forbidden' and lets everything else through"""
    gk = start_gk({"Gatekeeper::Auth": {"LuaAuth": "required;RRQ,ARQ"},
                   "LuaAuth": {"RegistrationScript": 'if string.find(aliases, "bad") then result = "FAIL" '
                                                     'else result = "OK" end',
                               "CallScript": 'if calledAlias == "forbidden" then result = "FAIL" '
                                             'else result = "OK" end'}})
    lua_or_skip(gk)
    bad = Endpoint(workdir, "pub1", "badguy").start(duration=1, timeout=4).wait()
    assert not bad["registered"] and bad["registrationRejected"], bad
    forbidden = Endpoint(workdir, "pub2", "forbidden").start(duration=30)
    bob = Endpoint(workdir, "pub2", "bob").start(duration=30)
    try:
        assert gk.wait_registered("forbidden") and gk.wait_registered("bob")
        refused = dial(gk, workdir, "forbidden", "forbidden")
        allowed = dial(gk, workdir, "bob", "bob")
    finally:
        forbidden.kill()
        bob.kill()
    assert not refused["connected"] and arj_count(gk) == 1, refused
    assert allowed["connected"], allowed


def test_lua_routing(start_gk, workdir):
    """lua routing policy: the script rewrites '#' to '*' style aliases (sales -> bob), sends 'support' to an IP,
    rejects 'blocked' and skips everything else to the next policy"""
    script = ('if calledAlias == "sales" then destAlias = "bob" '
              'elseif calledAlias == "support" then destIP = "%s" '
              'elseif calledAlias == "blocked" then action = "REJECT" '
              'else action = "SKIP" end' % PUB2)
    gk = start_gk({"RoutingPolicy": {"default": "lua,internal"}, "Routing::Lua": {"Script": script}})
    lua_or_skip(gk)
    bob = Endpoint(workdir, "pub2", "bob").start(duration=40, calls=2)
    support = Endpoint(workdir, "pub2", "support", no_gk=True, listen_port=1720).start(duration=40)
    try:
        assert gk.wait_registered("bob")
        sales = dial(gk, workdir, "sales", "sales")
        ip = dial(gk, workdir, "support", "support")
        blocked = dial(gk, workdir, "blocked", "blocked")
        direct = dial(gk, workdir, "bob", "direct")
        bob_result, support_result = bob.wait(), support.wait()
    finally:
        bob.kill()
        support.kill()
    assert sales["connected"] and ip["connected"] and direct["connected"], (sales, ip, direct)
    assert not blocked["connected"], blocked
    assert bob_result["callsConnected"] == 2 and support_result["connected"], (bob_result, support_result)


def test_lua_accounting(start_gk, workdir):
    """LuaAcct: the script gets every event with its CDR parameters and writes them to a file"""
    log = os.path.join(workdir, "lua-acct.txt")
    script = ('local f = io.open("%s", "a") f:write(event .. "|" .. (param_Calling_Station_Id or "") .. "|" '
              '.. (param_d or "") .. "\\n") f:close() result = "OK"' % log)
    gk = start_gk({"Gatekeeper::Acct": {"LuaAcct": "required;start,connect,stop", "FileAcct": "required;stop"},
                   "LuaAcct": {"Script": script}})
    lua_or_skip(gk)
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller,1001"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"), duration=3)
    assert caller["connected"], caller
    lines = [line.strip().split("|") for line in open(log)]
    assert [line[0] for line in lines] == ["Start", "Connect", "Stop"], lines
    assert lines[0][1] == "1001" and int(lines[2][2]) >= 2, lines


@pytest.mark.parametrize("script", [
    'error("boom")',
    'local x = nil; x.y = 1',
    'while true do end',
    'this is not lua',
], ids=["error", "nil-index", "endless-loop", "syntax-error"])
def test_lua_script_failure(start_gk, workdir, script):
    """a routing script that fails (error, nil index, syntax error): GnuGk logs it and goes on with the next
    policy; an endless loop must not hang GnuGk's other work (status port, registrations)"""
    gk = start_gk({"RoutingPolicy": {"default": "lua,internal"}, "Routing::Lua": {"Script": script}})
    lua_or_skip(gk)
    bob = Endpoint(workdir, "pub2", "bob").start(duration=30)
    try:
        assert gk.wait_registered("bob")
        caller = Endpoint(workdir, "pub1", "caller").start(call="bob", duration=1, timeout=8)
        time.sleep(2)
        started = time.time()
        version = gk.command("Version", "Version:")
        status_time = time.time() - started
        other = Endpoint(workdir, "pub1", "other").start(duration=0, timeout=5).wait()
        caller_result = caller.wait(timeout=30)
    finally:
        bob.kill()
    assert "Version" in version and status_time < 3, "the status port hangs"
    assert other["registered"], "registrations hang while the script runs"
    assert gk.alive()
    if "while" not in script:
        assert caller_result["connected"], "a failing script should fall through to the next policy: %s" % caller_result
