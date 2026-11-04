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
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"alice": "sigip:%s:1720" % PUB1},
    })
    assert Endpoint(workdir, "pub1", "alice").start(duration=1).wait()["registered"]
    wrong_ip = Endpoint(workdir, "pub2", "alice", name="alice-pub2").start(duration=1, timeout=5).wait()
    assert not wrong_ip["registered"] and wrong_ip["registrationRejected"]
    unlisted = Endpoint(workdir, "pub1", "bob").start(duration=1, timeout=5).wait()
    assert not unlisted["registered"], "alias without rule registered"


# 10.99.0.11 (pub1) as it appears in the printed signal address the sigaddr regex is matched against
PUB1_HEX = "0a 63 00 0b"
RRQ_AUTH_RULES = [
    # (id, rule for alice, host, endpoint instance (0: port 1720, 1: port 1730), registers, marks)
    ("sigip-port", "sigip:%s:1730" % PUB1, "pub1", 1, True),
    ("sigip-wrong-port", "sigip:%s:1730" % PUB1, "pub1", 0, False),
    ("sigip-default-port", "sigip:%s" % PUB1, "pub1", 0, True),
    ("sigip-not-default-port", "sigip:%s" % PUB1, "pub1", 1, False),
    ("sigip-wrong-ip", "sigip:%s:1720" % PUB1, "pub2", 0, False),
    ("sigaddr", "sigaddr:.*ip = .* %s .*port = 1720.*" % PUB1_HEX, "pub1", 0, True),
    ("sigaddr-wrong-ip", "sigaddr:.*ip = .* %s .*port = 1720.*" % PUB1_HEX, "pub2", 0, False),
    ("sigaddr-network", "sigaddr:.*ip = .* 0a 63 00 .*port = 1720.*", "pub2", 0, True),
    ("sigaddr-wrong-port", "sigaddr:.*ip = .* %s .*port = 1720.*" % PUB1_HEX, "pub1", 1, False),
    ("allow", "allow", "pub2", 0, True),
    ("deny", "deny", "pub1", 0, False),
]


@pytest.mark.parametrize("rule,host,instance,registers", [
    pytest.param(*r[1:5], id=r[0], marks=r[5:]) for r in RRQ_AUTH_RULES])
def test_rrq_auth_rules(start_gk, workdir, rule, host, instance, registers):
    """[RasSrv::RRQAuth] rule types: sigip with and without port, sigaddr regular expressions, allow, deny"""
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"alice": rule},
    })
    result = Endpoint(workdir, host, "alice", instance=instance).start(duration=1, timeout=5).wait()
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
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"6019901": "sigip:%s:1720" % PUB1, "6019902": "sigip:%s:1720" % PUB2},
    })
    result = Endpoint(workdir, host, aliases).start(duration=1, timeout=5).wait()
    assert result["registered"] == registers, result
    if not registers:
        assert gk.rejected_registration(aliases.split(",")[0]) == "securityDenial", gk.ras_events("RRJ")


@pytest.mark.parametrize("rule,registers", [
    ("sigip:%s:1720&sigaddr:.*port = 1730.*" % PUB1, False),	# the IP matches, the port doesn't
    ("sigip:%s:1720&sigaddr:.*port = 1720.*" % PUB1, True),
    ("sigip:%s:1720&deny" % PUB1, False),
    ("sigip:%s:1720|sigip:%s:1720" % (PUB2, PUB1), True),	# '|' separates alternatives
    ("sigip:%s:1720|sigip:%s:1720&sigaddr:.*port = 1730.*" % (PUB2, PUB1), False),
], ids=["and-one-fails", "and-all-apply", "and-deny", "or", "or-and-fails"])
def test_rrq_auth_conditions(start_gk, workdir, rule, registers):
    """conditions separated by '&' must all apply (manual), '|' separates alternatives"""
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"alice": rule},
    })
    result = Endpoint(workdir, "pub1", "alice").start(duration=1, timeout=5).wait()
    assert result["registered"] == registers, result


def test_rrq_auth_alias_order_and_default(start_gk, workdir):
    """the first alias that has a rule decides, aliases without a rule use the 'default' rule"""
    gk = start_gk({
        "Gatekeeper::Auth": {"AliasAuth": "required;RRQ"},
        "RasSrv::RRQAuth": {"alice": "sigip:%s:1720" % PUB1, "default": "sigip:%s:1720" % PUB2},
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
