"""Registration rules: duplicate aliases, keep-alive, expiry, additive registration."""

import time

import pytest

from harness import gnugk, topology

from harness.endpoint import Endpoint


def test_duplicate_alias(start_gk, workdir):
    """an alias registered from one IP is rejected from another IP, but the same endpoint can register
    again after a restart without unregistering"""
    gk = start_gk()
    first = Endpoint(workdir, "pub1", "alice").start(duration=30)
    try:
        assert gk.wait_registered("alice")
        other = Endpoint(workdir, "pub2", "alice", name="alice-other").start(duration=1, timeout=5)
        result = other.wait()
        assert not result["registered"]
        assert gk.rejected_registration("alice") == "duplicateAlias", gk.ras_events("RRJ")
    finally:
        first.kill()	# no URQ: GnuGk still has the registration

    assert "alice" in gk.registrations()
    again = Endpoint(workdir, "pub1", "alice", name="alice-again").start(duration=1)
    result = again.wait()
    assert result["registered"], "re-registration from the same IP was rejected"
    assert len(gk.ras_events("RRJ")) == 1


@pytest.mark.parametrize("auth", ["noauth", "md5", "h2351"])
def test_keepalive_reregistration(start_gk, workdir, auth):
    """with a short TimeToLive the endpoint keeps re-registering (lightweight RRQs, with tokens when
    authenticating) and stays registered"""
    config = [{"Gatekeeper::Main": {"TimeToLive": "10"}}]
    password = None
    if auth != "noauth":
        config.append(gnugk.md5_config() if auth == "md5" else gnugk.h2351_setup_config())
        password = "secret"
    gk = start_gk(*config, users={"alice": "secret"} if password else None)
    ep = Endpoint(workdir, "pub1", "alice", password=password, h2351=(auth == "h2351")).start(duration=28)
    try:
        assert gk.wait_registered("alice")
        time.sleep(25)
        assert "alice" in gk.registrations(), "registration expired"
    finally:
        result = ep.wait()
    assert result["registered"] and result["unregistered"]
    rrqs = gk.trace_count("RRQ Received from " + topology.HOST_IPS["pub1"])
    assert rrqs >= 3, "only %d RRQs in 25 seconds" % rrqs
    keepalives = gk.trace_count("keepAlive = true")
    assert keepalives >= 3, "only %d lightweight (keepAlive) RRQs" % keepalives
    assert not gk.ras_events("RRJ"), gk.ras_events("RRJ")


# GnuGk checks the registrations once a minute: without IRQ poll an endpoint expires up to 60 seconds
# after its TimeToLive, with the default IRQPollCount=1 one check later (after the unanswered IRQ)
@pytest.mark.parametrize("poll,low,high", [("0", 8, 75), ("1", 60, 135)], ids=["no-irq-poll", "irq-poll"])
def test_registration_expiry(start_gk, workdir, poll, low, high):
    """an endpoint that stops sending keep-alive RRQs is removed after its TimeToLive is over"""
    gk = start_gk({"Gatekeeper::Main": {"TimeToLive": "10"}, "RasSrv::RRQFeatures": {"IRQPollCount": poll}})
    ep = Endpoint(workdir, "pub1", "alice").start(duration=200)
    try:
        assert gk.wait_registered("alice")
        ep.pause()
        start = time.time()
        while "alice" in gk.registrations() and time.time() - start < high + 10:
            time.sleep(1)
        expired_after = time.time() - start
    finally:
        ep.resume()
        ep.kill()
    assert "alice" not in gk.registrations(), "registration didn't expire"
    assert low <= expired_after <= high, "expired after %.0f seconds" % expired_after
    irqs = gk.trace_count("infoRequest {")
    assert (irqs > 0) == (poll != "0"), "%d IRQs sent with IRQPollCount=%s" % (irqs, poll)


def additive_registration(gk, workdir, add, other=None):
    """alice registers and adds aliases with an additive (keep-alive) RRQ; returns alice's result and the
    registered aliases while she is still registered"""
    others = []
    if other:
        others.append(Endpoint(workdir, "pub2", other).start(duration=40))
        assert gk.wait_registered(other)
    alice = Endpoint(workdir, "pub1", "alice", add_aliases=add).start(duration=12)
    try:
        assert gk.wait_registered("alice")
        time.sleep(9)	# TimeToLive=5: the next keep-alive RRQ is the additive one
        aliases = gk.registrations()
        result = alice.wait()
    finally:
        for ep in [alice] + others:
            ep.kill()
    assert result["additiveRRQSent"], "no additive RRQ sent"
    return result, aliases


ADDITIVE_CONFIG = {"Gatekeeper::Main": {"TimeToLive": "5"}}


def test_additive_registration(start_gk, workdir):
    """an additive RRQ adds aliases to the registration"""
    gk = start_gk(ADDITIVE_CONFIG)
    _, aliases = additive_registration(gk, workdir, ["alice2", "2001"])
    assert {"alice", "alice2", "2001"} <= aliases, aliases
    assert not gk.ras_events("RRJ")


@pytest.mark.parametrize("add", [["bob"], ["alice", "bob"]], ids=["other-alias", "own-and-other-alias"])
def test_additive_registration_conflict(start_gk, workdir, add):
    """adding another endpoint's alias is rejected, also when the list contains one of the own aliases
    first (49d3ff9); the other endpoint keeps its alias"""
    gk = start_gk(ADDITIVE_CONFIG)
    _, aliases = additive_registration(gk, workdir, add, other="bob")
    # the RRJ event lists the aliases of the additive RRQ, so look for alice's IP
    rrj = [e for e in gk.ras_events("RRJ") if e[1] == topology.HOST_IPS["pub1"]]
    assert rrj and rrj[0][-1] == "invalidTerminalAliases", gk.ras_events("RRJ")
    assert "bob" in aliases
