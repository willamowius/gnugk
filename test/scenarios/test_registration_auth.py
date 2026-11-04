"""Registration checks for MD5 (cryptoEPPwdHash) and H.235.1 (Procedure I) tokens that don't need a call."""

import pytest

from harness import gnugk
from harness.endpoint import Endpoint

TOKENS = {
    "md5": (gnugk.md5_config, False),
    "h2351": (gnugk.h2351_setup_config, True),
}


@pytest.mark.parametrize("tokens", list(TOKENS))
@pytest.mark.parametrize("h46018,host", [(False, "pub1"), (True, "priv1")], ids=["public", "h46018"])
def test_correct_password(start_gk, workdir, tokens, h46018, host):
    auth_config, h2351 = TOKENS[tokens]
    config = [auth_config()] + ([gnugk.h46018_config()] if h46018 else [])
    gk = start_gk(*config, users={"alice": "secret"})
    if h46018:
        gk.require("h46018")
    result = Endpoint(workdir, host, "alice", password="secret", h46018=h46018, h2351=h2351).start(duration=1).wait()
    assert result["registered"]
    assert result["unregistered"], "URQ with token was rejected"
    assert "alice" not in gk.registrations()


@pytest.mark.parametrize("tokens", list(TOKENS))
@pytest.mark.parametrize("password", ["wrong", None], ids=["wrong-password", "no-token"])
def test_rejected(start_gk, workdir, tokens, password):
    auth_config, h2351 = TOKENS[tokens]
    gk = start_gk(auth_config(), users={"alice": "secret"})
    result = Endpoint(workdir, "pub1", "alice", password=password, h2351=h2351).start(duration=1, timeout=5).wait()
    assert not result["registered"]
    # H323Plus ignores an RRJ without H.235.1 token, so check what GnuGk sent instead of the endpoint's view
    assert gk.rejected_registration("alice") == "securityDenial"
    assert "alice" not in gk.registrations()


@pytest.mark.parametrize("tokens", list(TOKENS))
def test_unknown_user_rejected(start_gk, workdir, tokens):
    auth_config, h2351 = TOKENS[tokens]
    gk = start_gk(auth_config(), users={"alice": "secret"})
    result = Endpoint(workdir, "pub1", "mallory", password="secret", h2351=h2351).start(duration=1, timeout=5).wait()
    assert not result["registered"]
    assert gk.rejected_registration("mallory") == "securityDenial"
    assert "mallory" not in gk.registrations()
