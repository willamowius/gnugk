"""SQL backed modules with SQLite: SQLPasswordAuth, SQLAliasAuth, SQLAuth, the SQL routing policy."""

import os
import sqlite3

import pytest

from harness import pcap, topology
from harness.calls import run_call
from harness.endpoint import Endpoint
from scenarios.test_multi_gk import neighbor

PUB1, PUB2 = topology.HOST_IPS["pub1"], topology.HOST_IPS["pub2"]


def database(workdir, statements):
    path = os.path.join(workdir, "gnugk.db")
    con = sqlite3.connect(path)
    for statement in statements:
        con.execute(statement)
    con.commit()
    con.close()
    return path


def sql_section(path, query, **extra):
    section = {"Driver": "SQLite", "Database": path, "Query": query}
    section.update(extra)
    return section


@pytest.mark.parametrize("password,registers", [("secret", True), ("wrong", False)])
def test_sql_password_auth(start_gk, workdir, password, registers):
    """SQLPasswordAuth: MD5 passwords from the database"""
    db = database(workdir, ["CREATE TABLE users (alias TEXT, password TEXT)",
                            "INSERT INTO users VALUES ('alice', 'secret')"])
    gk = start_gk({
        "Gatekeeper::Auth": {"SQLPasswordAuth": "required;RRQ,URQ,ARQ,BRQ,DRQ"},
        "SQLPasswordAuth": sql_section(db, "SELECT password FROM users WHERE alias = '%1'"),
    })
    result = Endpoint(workdir, "pub1", "alice", password=password).start(duration=1, timeout=5).wait()
    assert result["registered"] == registers, result
    if registers:
        assert result["unregistered"], "URQ rejected"
    else:
        assert gk.rejected_registration("alice") == "securityDenial", gk.ras_events("RRJ")


def test_sql_alias_auth(start_gk, workdir):
    """SQLAliasAuth: the database gives the address an alias may register from"""
    alice = Endpoint(workdir, "pub1", "alice")
    db = database(workdir, ["CREATE TABLE rules (alias TEXT, rule TEXT)",
                            "INSERT INTO rules VALUES ('alice', 'sigip:%s:%d')" % (PUB1, alice.listen_port)])
    gk = start_gk({
        "Gatekeeper::Auth": {"SQLAliasAuth": "required;RRQ"},
        "SQLAliasAuth": sql_section(db, "SELECT rule FROM rules WHERE alias = '%1'"),
    })
    assert alice.start(duration=1).wait()["registered"]
    wrong_ip = Endpoint(workdir, "pub2", "alice", name="alice-pub2").start(duration=1, timeout=5).wait()
    assert not wrong_ip["registered"]
    unknown = Endpoint(workdir, "pub1", "bob").start(duration=1, timeout=5).wait()
    assert not unknown["registered"]


@pytest.mark.parametrize("dialed,connects", [("777", True), ("888", False)], ids=["rewrite", "reject"])
def test_sql_routing(start_gk, workdir, dialed, connects):
    """the sql routing policy turns 777 into the callee's alias and rejects 888"""
    db = database(workdir, ["CREATE TABLE routes (called TEXT, destination TEXT)",
                            "INSERT INTO routes VALUES ('777', 'callee')",
                            "INSERT INTO routes VALUES ('888', 'REJECT')"])
    gk = start_gk({
        "RoutingPolicy": {"default": "sql,explicit,internal"},
        "Routing::Sql": sql_section(db, "SELECT destination FROM routes WHERE called = '%c'"),
    })
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), dialed,
                              callee=Endpoint(workdir, "pub2", "callee"), callee_duration=10)
    assert caller["connected"] == connects, caller
    assert callee["connected"] == connects, callee
    if not connects:
        assert gk.ras_events("ARJ"), "no ARJ"


def sql_auth(db, checks, **queries):
    """[Gatekeeper::Auth] SQLAuth=required;<checks> and the [SQLAuth] section with the given queries"""
    section = {"Driver": "SQLite", "Database": db}
    section.update(queries)
    return {"Gatekeeper::Auth": {"SQLAuth": "required;" + checks}, "SQLAuth": section}


@pytest.mark.parametrize("alias,host,reject_reason", [
    ("alice", "pub1", None),
    ("alice", "pub2", "resourceUnavailable"),	# no row for this IP
    ("dave", "pub1", "securityDenial"),	# disabled
    ("nobody", "pub1", "resourceUnavailable"),	# no row at all
], ids=["allowed", "wrong-ip", "disabled", "unknown"])
def test_sql_auth_registration(start_gk, workdir, alias, host, reject_reason):
    """SQLAuth RegQuery: the first column of the first row decides (securityDenial), no row means
    failure for a required rule (resourceUnavailable)"""
    db = database(workdir, ["CREATE TABLE users (h323id TEXT, ip TEXT, enabled INTEGER)",
                            "INSERT INTO users VALUES ('alice', '%s', 1)" % PUB1,
                            "INSERT INTO users VALUES ('dave', '%s', 0)" % PUB1])
    gk = start_gk(sql_auth(db, "RRQ",
                           RegQuery="SELECT enabled FROM users WHERE h323id = '%u' AND ip = '%{callerip}'"))
    result = Endpoint(workdir, host, alias).start(duration=1, timeout=5).wait()
    assert result["registered"] == (reject_reason is None), result
    if reject_reason:
        assert gk.rejected_registration(alias) == reject_reason, gk.ras_events("RRJ")


def test_sql_auth_registration_aliases(start_gk, workdir):
    """SQLAuth RegQuery with an 'aliases' column: the endpoint is registered with these aliases (others it
    sent are dropped), and can be called on them"""
    db = database(workdir, ["CREATE TABLE users (h323id TEXT, aliases TEXT)",
                            "INSERT INTO users VALUES ('callee', 'callee,2002')",
                            "INSERT INTO users VALUES ('caller', 'caller')"])
    gk = start_gk(sql_auth(db, "RRQ", RegQuery="SELECT 1, aliases FROM users WHERE h323id = '%u'"))
    callee_ep = Endpoint(workdir, "pub2", "callee,9999").start(duration=30)
    try:
        assert gk.wait_registered("2002"), gk.registrations()
        assert "9999" not in gk.registrations(), gk.registrations()
        caller, _ = run_call(gk, Endpoint(workdir, "pub1", "caller"), "2002")
        callee = callee_ep.wait()
    finally:
        callee_ep.kill()
    assert caller["connected"] and callee["connected"], caller["endReason"]


@pytest.mark.parametrize("dialed,connects", [("callee", True), ("other", False)], ids=["allowed", "denied"])
def test_sql_auth_call(start_gk, workdir, dialed, connects):
    """SQLAuth CallQuery on ARQ: who may call what"""
    db = database(workdir, ["CREATE TABLE calls (caller TEXT, called TEXT, allowed INTEGER)",
                            "INSERT INTO calls VALUES ('caller', 'callee', 1)",
                            "INSERT INTO calls VALUES ('caller', 'other', 0)"])
    # (the callee's answering ARQ goes through the query too)
    gk = start_gk(sql_auth(db, "ARQ", CallQuery="SELECT allowed FROM calls WHERE caller = '%u' "
                                                "AND called = '%{Called-Station-Id}' "
                                                "UNION ALL SELECT 1 WHERE %{answer} = 1"))
    callees = [Endpoint(workdir, "pub2", "callee"), Endpoint(workdir, "pub2", "other")]
    for ep in callees:
        ep.start(duration=20)
    try:
        assert gk.wait_registered("callee") and gk.wait_registered("other")
        caller, _ = run_call(gk, Endpoint(workdir, "pub1", "caller"), dialed)
    finally:
        for ep in callees:
            ep.kill()
    assert caller["connected"] == connects, caller
    if not connects:
        assert [e for e in gk.ras_events("ARJ") if e[5] == "securityDenial"], gk.ras_events("ARJ")


def test_sql_auth_setup_q931cause(start_gk, workdir):
    """SQLAuth CallQuery on Setup: a denied call is released with the 'q931cause' from the database"""
    db = database(workdir, ["CREATE TABLE calls (called TEXT, allowed INTEGER, q931cause INTEGER)",
                            "INSERT INTO calls VALUES ('callee', 0, 17)"])
    gk = start_gk(sql_auth(db, "Setup", CallQuery="SELECT allowed, q931cause FROM calls "
                                                  "WHERE called = '%{Called-Station-Id}' AND %{arq} = 0"))
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"), callee_duration=10)
    assert caller["registered"] and not caller["connected"], caller
    assert caller["q931Cause"] == 17, caller
    assert not callee["callAttempted"], "the call reached the callee"


@pytest.mark.parametrize("host,connects", [("pub1", True), ("pub2", False)])
def test_sql_auth_unregistered_caller(start_gk, workdir, host, connects):
    """SQLAuth CallQuery for calls from unregistered endpoints (SetupUnreg): only from pub1"""
    db = database(workdir, ["CREATE TABLE hosts (ip TEXT)", "INSERT INTO hosts VALUES ('%s')" % PUB1])
    gk = start_gk({"RoutedMode": {"AcceptUnregisteredCalls": "1"}},
                  sql_auth(db, "SetupUnreg", CallQuery="SELECT %{from-registered} = 0 FROM hosts "
                                                       "WHERE ip = '%{callerip}' UNION ALL SELECT 0"))
    callee_host = "pub2" if host == "pub1" else "pub1"
    caller, callee = run_call(gk, Endpoint(workdir, host, "caller", no_gk=True), "callee@" + topology.GK_IP,
                              callee=Endpoint(workdir, callee_host, "callee"), callee_duration=10)
    assert caller["connected"] == connects, caller
    assert callee["connected"] == connects, callee


def test_sql_auth_credittime(start_gk, workdir):
    """SQLAuth CallQuery 'credittime': the call is ended after that many seconds"""
    db = database(workdir, [])
    gk = start_gk(sql_auth(db, "ARQ", CallQuery="SELECT 1, 4 AS credittime"))
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"), duration=15)
    assert caller["connected"] and callee["connected"], caller["endReason"]
    assert caller["endReason"] != "EndedByLocalUser", caller["endReason"]
    assert 3000 <= caller["durationMs"] <= 7000, caller["durationMs"]
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and 3 <= int(cdrs[0]["duration"]) <= 6, cdrs


def test_sql_auth_redirectnumber(start_gk, workdir):
    """SQLAuth CallQuery 'redirectnumber': the call to 777 goes to the callee"""
    db = database(workdir, ["CREATE TABLE redirects (dialed TEXT, target TEXT)",
                            "INSERT INTO redirects VALUES ('777', 'callee')"])
    gk = start_gk(sql_auth(db, "ARQ", CallQuery="SELECT 1, target AS redirectnumber FROM redirects "
                                                "WHERE dialed = '%{Called-Station-Id}' AND %{answer} = 0 "
                                                "UNION ALL SELECT 1, NULL WHERE %{answer} = 1"))
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "777",
                              callee=Endpoint(workdir, "pub2", "callee"))
    assert caller["connected"] and callee["connected"], caller["endReason"]
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["callee_ip"] == PUB2, cdrs


def test_sql_auth_redirectip(start_gk, workdir):
    """SQLAuth CallQuery 'redirectip': the call goes to an unregistered endpoint at that address"""
    db = database(workdir, [])
    callee_ep = Endpoint(workdir, "pub2", "callee", no_gk=True)
    gk = start_gk(sql_auth(db, "ARQ", CallQuery="SELECT 1, '%s:%d' AS redirectip" % (PUB2, callee_ep.listen_port)))
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "somewhere", callee=callee_ep)
    assert caller["connected"] and callee["connected"], caller["endReason"]
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["callee_ip"] == PUB2, cdrs


@pytest.mark.parametrize("proxy_enabled,column,proxied", [("1", "0", False), ("0", "1", True)],
                         ids=["proxy-off", "proxy-on"])
def test_sql_auth_proxy(start_gk, workdir, capture, proxy_enabled, column, proxied):
    """SQLAuth CallQuery 'proxy': turn the RTP proxy off or on for a call"""
    db = database(workdir, [])
    gk = start_gk({"Proxy": {"Enable": proxy_enabled}},
                  sql_auth(db, "ARQ", CallQuery="SELECT 1, %s AS proxy" % column))
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"))
    assert caller["connected"] and callee["connected"], caller["endReason"]
    for side, other in ((caller, callee), (callee, caller)):
        assert side["rtpReceived"] >= 0.8 * other["rtpSent"] > 0, (side, other)
    assert bool(pcap.ports_used(capture, topology.GK_IP, "UDP", 40000, 41999)) == proxied


def test_sql_auth_clientauthid(start_gk, workdir):
    """SQLAuth CallQuery 'clientauthid': stored with the call and written to the CDR"""
    db = database(workdir, [])
    gk = start_gk(sql_auth(db, "ARQ", CallQuery="SELECT 1, 123456789012 AS clientauthid"))
    caller, callee = run_call(gk, Endpoint(workdir, "pub1", "caller"), "callee",
                              callee=Endpoint(workdir, "pub2", "callee"))
    assert caller["connected"], caller["endReason"]
    cdrs = gk.cdrs()
    assert len(cdrs) == 1 and cdrs[0]["client_auth_id"] == "123456789012", cdrs


NEIGHBOR_NOT_CHECKED = pytest.mark.xfail(strict=True, reason="LRQs from configured neighbors skip all "
    "authenticators (RasSrv.cxx: 'neighbors do not need validation'), NbQuery only runs for non-neighbor LRQs "
    "with AcceptNonNeighborLRQ=1, the manual says it authorizes LRQs from neighbors (%{nbid})")


@pytest.mark.parametrize("configured,allowed", [
    (True, True),
    pytest.param(True, False, marks=NEIGHBOR_NOT_CHECKED),
    (False, True),
    (False, False),
], ids=["neighbor-allowed", "neighbor-denied", "non-neighbor-allowed", "non-neighbor-denied"])
def test_sql_auth_lrq(start_gk, workdir, configured, allowed):
    """SQLAuth NbQuery on GK2: LRQs from GK1 are only answered when the database allows it, GK1 is a
    configured neighbor of GK2, or not (then GK2 accepts its LRQs with AcceptNonNeighborLRQ=1)"""
    gk1_ip, gk2_ip = topology.GK_IP, topology.HOST_IPS["gk2"]
    db = database(workdir, ["CREATE TABLE neighbors (ip TEXT)"]
                  + (["INSERT INTO neighbors VALUES ('%s')" % gk1_ip] if allowed else []))
    start_gk({"Gatekeeper::Main": {"Name": "GK1"}}, neighbor("GK2", gk2_ip))
    gk2_config = [{"Gatekeeper::Main": {"Name": "GK2"}},
                  sql_auth(db, "LRQ", NbQuery="SELECT 1 FROM neighbors WHERE ip = '%{nbip}' UNION ALL SELECT 0")]
    if configured:
        gk2_config.append(neighbor("GK1", gk1_ip))
    else:
        # (GK1's Setup then comes from an unknown gatekeeper, an unregistered call for GK2)
        gk2_config.append({"RasSrv::LRQFeatures": {"AcceptNonNeighborLRQ": "1"},
                           "RoutedMode": {"AcceptUnregisteredCalls": "1"}})
    gk2 = start_gk(*gk2_config, host="gk2", name="gk2")
    caller, callee = run_call(gk2, Endpoint(workdir, "pub1", "alice", gk="gk"), "bob",
                              callee=Endpoint(workdir, "pub2", "bob", gk="gk2"), callee_duration=12)
    assert caller["connected"] == allowed, caller
    assert bool(gk2.ras_events("LCF")) == allowed, gk2.ras_events("LCF")
    if not allowed:
        assert gk2.ras_events("LRJ"), "no LRJ"


SQL_CASE = ("the database compares the alias (SQLite's = is case-sensitive), GnuGk passes the alias as received "
            "whatever CompareAliasCase says; a query can use eg. COLLATE NOCASE")
CASE_PARAMS = [pytest.param("1", False, id="case-sensitive"),
               pytest.param("0", True, id="case-insensitive", marks=pytest.mark.xfail(strict=True, reason=SQL_CASE))]


@pytest.mark.parametrize("compare_case,registers", CASE_PARAMS)
def test_sql_password_auth_alias_case(start_gk, workdir, compare_case, registers):
    """SQLPasswordAuth: the password of 'alice' is only used for 'Alice' with CompareAliasCase=0"""
    db = database(workdir, ["CREATE TABLE users (alias TEXT, password TEXT)",
                            "INSERT INTO users VALUES ('alice', 'secret')"])
    gk = start_gk({
        "Gatekeeper::Main": {"CompareAliasCase": compare_case},
        "Gatekeeper::Auth": {"SQLPasswordAuth": "required;RRQ,URQ,ARQ,BRQ,DRQ"},
        "SQLPasswordAuth": sql_section(db, "SELECT password FROM users WHERE alias = '%1'"),
    })
    result = Endpoint(workdir, "pub1", "Alice", password="secret").start(duration=1, timeout=5).wait()
    assert result["registered"] == registers, result


@pytest.mark.parametrize("compare_case,registers", CASE_PARAMS)
def test_sql_alias_auth_alias_case(start_gk, workdir, compare_case, registers):
    """SQLAliasAuth: the rule of 'alice' is only used for 'Alice' with CompareAliasCase=0"""
    endpoint = Endpoint(workdir, "pub1", "Alice")
    db = database(workdir, ["CREATE TABLE rules (alias TEXT, rule TEXT)",
                            "INSERT INTO rules VALUES ('alice', 'sigip:%s:%d')" % (PUB1, endpoint.listen_port)])
    gk = start_gk({
        "Gatekeeper::Main": {"CompareAliasCase": compare_case},
        "Gatekeeper::Auth": {"SQLAliasAuth": "required;RRQ"},
        "SQLAliasAuth": sql_section(db, "SELECT rule FROM rules WHERE alias = '%1'"),
    })
    assert endpoint.start(duration=1, timeout=5).wait()["registered"] == registers


@pytest.mark.parametrize("compare_case,registers", CASE_PARAMS)
def test_sql_auth_registration_alias_case(start_gk, workdir, compare_case, registers):
    """SQLAuth RegQuery with %u: the row of 'alice' is only used for 'Alice' with CompareAliasCase=0"""
    db = database(workdir, ["CREATE TABLE users (h323id TEXT, enabled INTEGER)",
                            "INSERT INTO users VALUES ('alice', 1)"])
    gk = start_gk({"Gatekeeper::Main": {"CompareAliasCase": compare_case}},
                  sql_auth(db, "RRQ", RegQuery="SELECT enabled FROM users WHERE h323id = '%u'"))
    assert Endpoint(workdir, "pub1", "Alice").start(duration=1, timeout=5).wait()["registered"] == registers
