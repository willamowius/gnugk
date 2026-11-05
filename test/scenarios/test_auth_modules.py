"""Authentication / authorization modules without passwords: FileIPAuth, AliasAuth, PrefixAuth."""

import pytest

from harness import topology
from harness.calls import run_call
from harness.endpoint import Endpoint

PUB1 = topology.HOST_IPS["pub1"]
PUB2 = topology.HOST_IPS["pub2"]


def call_result(gk, workdir, caller_host, caller_alias, callee_host, callee_alias, dialed):
    caller, callee = run_call(gk, Endpoint(workdir, caller_host, caller_alias), dialed,
                              callee=Endpoint(workdir, callee_host, callee_alias), callee_duration=12)
    return caller, callee


def test_file_ip_auth(start_gk, workdir):
    """FileIPAuth: registration by IP, and the prefixes an IP may call"""
    # the network entry lets the callee (PUB2) register
    gk = start_gk({
        "Gatekeeper::Auth": {"FileIPAuth": "required;RRQ,ARQ"},
        "FileIPAuth": {PUB1: "allow;20", "10.99.0.0/28": "allow", "any": "reject"},
    })
    # allowed prefix
    caller, callee = call_result(gk, workdir, "pub1", "caller", "pub2", "callee,2002", "2002")
    assert caller["registered"] and caller["connected"], caller
    # prefix not in the caller's list
    caller, _ = call_result(gk, workdir, "pub1", "caller", "pub2", "callee,2002", "callee")
    assert caller["registered"] and not caller["connected"], caller
    assert [e for e in gk.ras_events("ARJ") if e[5] == "securityDenial"], gk.ras_events("ARJ")
    # rejected IP (priv1 is hidden behind its NAT router 10.99.0.21, outside 10.99.0.0/28, so 'any' applies)
    result = Endpoint(workdir, "priv1", "mallory").start(duration=1, timeout=5).wait()
    assert not result["registered"] and result["registrationRejected"]


def test_file_ip_auth_prefix_entry_allows_rrq(start_gk, workdir):
    """manual example #1: IP=allow;prefixes with any=reject still lets that IP register and unregister,
    the prefixes are only checked on ARQ and Setup"""
    gk = start_gk({
        "Gatekeeper::Auth": {"FileIPAuth": "required;GRQ,RRQ,URQ,ARQ"},
        "FileIPAuth": {PUB1: "allow;20", "any": "reject"},
    })
    result = Endpoint(workdir, "pub1", "caller").start(duration=1, timeout=5).wait()
    assert result["registered"], "the endpoint can't register"
    assert result["unregistered"], "the endpoint can't unregister"


def test_file_ip_auth_prefix_entry_call_by_ip(start_gk, workdir):
    """an endpoint limited to some prefixes can't get around them by calling an IP (ARQ without number)"""
    gk = start_gk({
        "Gatekeeper::Auth": {"FileIPAuth": "required;RRQ,ARQ"},
        "FileIPAuth": {PUB1: "allow;20", "any": "reject"},
        "RoutingPolicy": {"default": "explicit,internal"},
    })
    caller, _ = run_call(gk, Endpoint(workdir, "pub1", "caller"), PUB2,
                         callee=Endpoint(workdir, "pub2", "callee", no_gk=True), callee_duration=12)
    assert caller["registered"] and not caller["connected"], caller
    assert [e for e in gk.ras_events("ARJ") if e[5] == "securityDenial"], gk.ras_events("ARJ")


def test_alias_auth(start_gk, workdir):
    """AliasAuth: an alias may only register from its configured signaling address"""
    alice = Endpoint(workdir, "pub1", "alice")
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"alice": "sigip:%s:%d" % (PUB1, alice.listen_port)},
    })
    assert alice.start(duration=1).wait()["registered"]
    wrong_ip = Endpoint(workdir, "pub2", "alice", name="alice-pub2").start(duration=1, timeout=5).wait()
    assert not wrong_ip["registered"] and wrong_ip["registrationRejected"]
    unlisted = Endpoint(workdir, "pub1", "bob").start(duration=1, timeout=5).wait()
    assert not unlisted["registered"], "alias without rule registered"


# pub1 and pub2 as they appear in the printed signal address the sigaddr regex is matched against
PUB1_HEX, PUB2_HEX = "0a 63 00 0b", "0a 63 00 0c"
# in the rules {port} is the endpoint's signaling port, {other} another one
RRQ_AUTH_RULES = [
    # (id, rule for alice, host, endpoint listens on 1720 (else on its own port), registers)
    ("sigip-port", "sigip:%s:{port}" % PUB1, "pub1", False, True),
    ("sigip-wrong-port", "sigip:%s:{other}" % PUB1, "pub1", False, False),
    ("sigip-default-port", "sigip:%s" % PUB1, "pub1", True, True),	# no port in the rule means 1720
    ("sigip-not-default-port", "sigip:%s" % PUB1, "pub1", False, False),
    ("sigip-wrong-ip", "sigip:%s:{port}" % PUB1, "pub2", False, False),
    ("sigaddr", "sigaddr:.*ip = .* %s .*port = {port}.*" % PUB1_HEX, "pub1", False, True),
    ("sigaddr-wrong-ip", "sigaddr:.*ip = .* %s .*port = {port}.*" % PUB1_HEX, "pub2", False, False),
    ("sigaddr-network", "sigaddr:.*ip = .* 0a 63 00 .*port = {port}.*", "pub2", False, True),
    ("sigaddr-wrong-port", "sigaddr:.*ip = .* %s .*port = {other}.*" % PUB1_HEX, "pub1", False, False),
    ("allow", "allow", "pub2", False, True),
    ("deny", "deny", "pub1", False, False),
]


def rrq_rule(rule, endpoint):
    return rule.format(port=endpoint.listen_port, other=endpoint.listen_port + 100)


@pytest.mark.parametrize("rule,host,on_1720,registers", [
    pytest.param(*r[1:5], id=r[0]) for r in RRQ_AUTH_RULES])
def test_rrq_auth_rules(start_gk, workdir, rule, host, on_1720, registers):
    """[RasSrv::RRQAuth] rule types: sigip with and without port, sigaddr regular expressions, allow, deny"""
    alice = Endpoint(workdir, host, "alice", listen_port=1720 if on_1720 else None)
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"alice": rrq_rule(rule, alice)},
    })
    result = alice.start(duration=1, timeout=5).wait()
    assert result["registered"] == registers, result
    if not registers:
        assert gk.rejected_registration("alice") == "securityDenial", gk.ras_events("RRJ")


@pytest.mark.parametrize("aliases,host,registers", [
    ("6019901", "pub1", True),
    ("6019901", "pub2", False),
    ("gw1,6019901", "pub1", True),	# gw1 has no rule, the number's rule applies
    ("gw1,6019901", "pub2", False),
], ids=["number-ok", "number-wrong-ip", "name-and-number-ok", "name-and-number-wrong-ip"])
def test_rrq_auth_e164_sigip(start_gk, workdir, aliases, host, registers):
    """the most common setup: E.164 numbers with sigip rules, eg. 6019901=sigip:<ip>:1720"""
    endpoint = Endpoint(workdir, host, aliases)
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"6019901": "sigip:%s:%d" % (PUB1, endpoint.listen_port),
                            "6019902": "sigip:%s:%d" % (PUB2, endpoint.listen_port)},
    })
    result = endpoint.start(duration=1, timeout=5).wait()
    assert result["registered"] == registers, result
    if not registers:
        assert gk.rejected_registration(aliases.split(",")[0]) == "securityDenial", gk.ras_events("RRJ")


@pytest.mark.parametrize("rule,registers", [
    ("sigip:%s:{port}&sigaddr:.*port = {other}.*" % PUB1, False),	# the IP matches, the port doesn't
    ("sigip:%s:{port}&sigaddr:.*port = {port}.*" % PUB1, True),
    ("sigip:%s:{port}&deny" % PUB1, False),
    ("sigip:%s:{port}|sigip:%s:{port}" % (PUB2, PUB1), True),	# '|' separates alternatives
    ("sigip:%s:{port}|sigip:%s:{port}&sigaddr:.*port = {other}.*" % (PUB2, PUB1), False),
], ids=["and-one-fails", "and-all-apply", "and-deny", "or", "or-and-fails"])
def test_rrq_auth_conditions(start_gk, workdir, rule, registers):
    """conditions separated by '&' must all apply (manual), '|' separates alternatives"""
    alice = Endpoint(workdir, "pub1", "alice")
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"alice": rrq_rule(rule, alice)},
    })
    result = alice.start(duration=1, timeout=5).wait()
    assert result["registered"] == registers, result


def test_rrq_auth_alias_order_and_default(start_gk, workdir):
    """the first alias that has a rule decides, aliases without a rule use the 'default' rule"""
    # IP only rules (sigaddr without port), the endpoints all have their own ports
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"alice": "sigaddr:.*ip = .* %s .*" % PUB1_HEX, "default": "sigaddr:.*ip = .* %s .*" % PUB2_HEX},
    })
    # bob has no rule, alice's rule applies
    assert Endpoint(workdir, "pub1", "bob,alice").start(duration=1, timeout=5).wait()["registered"]
    assert not Endpoint(workdir, "pub2", "bob,alice", name="bob-alice-pub2").start(duration=1, timeout=5).wait()["registered"]
    # no alias has a rule: the default rule
    assert Endpoint(workdir, "pub2", "carol").start(duration=1, timeout=5).wait()["registered"]
    assert not Endpoint(workdir, "pub1", "dave").start(duration=1, timeout=5).wait()["registered"]


def test_prefix_auth(start_gk, workdir):
    """PrefixAuth: who may call which prefix, by IP"""
    gk = start_gk({
        "Gatekeeper::Auth": {"PrefixAuth": "required;ARQ"},
        "PrefixAuth": {"20": "allow ipv4:%s/32|deny ipv4:0/0" % PUB1, "ALL": "deny ipv4:0/0"},
    })
    caller, callee = call_result(gk, workdir, "pub1", "caller,1001", "pub2", "callee,2002", "2002")
    assert caller["connected"] and callee["connected"], caller
    caller, _ = call_result(gk, workdir, "pub2", "callee,2002", "pub1", "caller,1001", "1001")
    assert caller["registered"] and not caller["connected"], caller
    assert [e for e in gk.ras_events("ARJ") if e[5] == "securityDenial"], gk.ras_events("ARJ")
