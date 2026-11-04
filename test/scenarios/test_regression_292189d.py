"""Suspected regression from commit 292189d ("fix auth bypass with unknown token OIDs").

Since that commit GkH235Authenticators::Validate() reports a RAS message without any token as
e_Absent, so a "required" SimplePasswordAuth rejects it. Before, a message from a registered
endpoint without tokens was accepted (H323Plus only reports a missing token when the remote ID
is set, which GnuGk never does).

Endpoints that only sign some of their RAS messages are affected, eg. endpoints that only put
tokens into RRQ and ARQ (like with Cisco Access Tokens), simulated here with MD5 tokens left out
of URQ and DRQ.

The tests assert the behaviour before 292189d, so they fail while the regression is present.
"""

import time

from harness import gnugk
from harness.endpoint import Endpoint

CALL_DURATION = 3


def md5_rule(messages):
    return {
        "Gatekeeper::Auth": {"SimplePasswordAuth": "required;" + messages},
        "SimplePasswordAuth": {"KeyFilled": gnugk.MD5_KEY},
    }


def call_with_unsigned_urq_drq(start_gk, workdir, messages):
    """MD5 call, the caller doesn't sign its URQ and DRQ; returns gk, caller result, callee result"""
    gk = start_gk(md5_rule(messages), users={"caller": "secretA", "callee": "secretB"})
    callee = Endpoint(workdir, "pub2", "callee", password="secretB", faststart=False)
    caller = Endpoint(workdir, "pub1", "caller", password="secretA", faststart=False, md5_unsigned=["URQ", "DRQ"])
    callee.start(duration=CALL_DURATION + 25)
    try:
        assert gk.wait_registered("callee"), "callee didn't register"
        caller.start(call="callee", duration=CALL_DURATION)
        caller_result = caller.wait()
        callee_result = callee.wait()
    finally:
        caller.kill()
        callee.kill()
    time.sleep(0.5)
    return gk, caller_result, callee_result


def check_urq_drq_accepted(gk, caller):
    assert caller["registered"] and caller["connected"], "call failed: %s" % caller["endReason"]
    drj = [event for event in gk.ras_events("DRJ")]
    assert not drj, "DRQ without token rejected: %s" % drj
    assert len(gk.ras_events("DCF")) == 2, "expected a DCF for both endpoints: %s" % gk.ras_events("DCF")
    assert caller["unregistered"], "URQ without token rejected"
    assert "caller" not in gk.registrations()


def test_unsigned_urq_drq_not_checked(start_gk, workdir):
    """control: URQ and DRQ aren't checked, works before and after 292189d"""
    gk, caller, _ = call_with_unsigned_urq_drq(start_gk, workdir, "RRQ,ARQ")
    check_urq_drq_accepted(gk, caller)


def test_unsigned_urq_drq_checked(start_gk, workdir):
    """URQ and DRQ are checked, but the endpoint only signs RRQ and ARQ"""
    gk, caller, _ = call_with_unsigned_urq_drq(start_gk, workdir, "RRQ,URQ,ARQ,BRQ,DRQ")
    check_urq_drq_accepted(gk, caller)

