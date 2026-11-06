"""Registration checks for MD5 (cryptoEPPwdHash) and H.235.1 (Procedure I) tokens that don't need a call."""

import pytest

from harness import gnugk
from harness.endpoint import Endpoint

TOKENS = {
    "md5": (gnugk.md5_config, False),
    "h2351": (gnugk.h2351_setup_config, True),
}


TOKENS_TEXT = {
    "md5": "MD5 tokens (SimplePasswordAuth on RRQ,URQ,ARQ,BRQ,DRQ)",
    "h2351": "H.235.1 tokens (SimplePasswordAuth on RRQ,URQ,ARQ,BRQ,DRQ,Setup)",
}


def describe_params(params):
    """description of the parameters, shown by --describe"""
    parts = [TOKENS_TEXT[params["tokens"]]] if "tokens" in params else []
    if "h46018" in params:
        parts.append("endpoint behind NAT with H.460.18" if params["h46018"] else "public endpoint")
    if "password" in params:
        parts.append("no token sent" if params["password"] is None else "wrong password")
    return "; ".join(parts)


@pytest.mark.parametrize("tokens", list(TOKENS))
@pytest.mark.parametrize("h46018,host", [(False, "pub1"), (True, "priv1")], ids=["public", "h46018"])
def test_correct_password(start_gk, workdir, tokens, h46018, host):
    """the right password: the endpoint registers and unregisters (the URQ token is accepted)"""
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
    """a wrong password or no token at all: GnuGk sends an RRJ with securityDenial, nothing is registered"""
    auth_config, h2351 = TOKENS[tokens]
    gk = start_gk(auth_config(), users={"alice": "secret"})
    result = Endpoint(workdir, "pub1", "alice", password=password, h2351=h2351).start(duration=1, timeout=5).wait()
    assert not result["registered"]
    # H323Plus ignores an RRJ without H.235.1 token, so check what GnuGk sent instead of the endpoint's view
    assert gk.rejected_registration("alice") == "securityDenial"
    assert "alice" not in gk.registrations()


@pytest.mark.parametrize("tokens", list(TOKENS))
def test_unknown_user_rejected(start_gk, workdir, tokens):
    """an alias without a password entry: RRJ securityDenial, also when the token itself is valid"""
    auth_config, h2351 = TOKENS[tokens]
    gk = start_gk(auth_config(), users={"alice": "secret"})
    result = Endpoint(workdir, "pub1", "mallory", password="secret", h2351=h2351).start(duration=1, timeout=5).wait()
    assert not result["registered"]
    assert gk.rejected_registration("mallory") == "securityDenial"
    assert "mallory" not in gk.registrations()


TOKEN_WARNING = "WARNING: SimplePasswordAuth checks "


def token_warnings(gk):
    with open(gk.trace_file, errors="replace") as f:
        return [line[line.index(TOKEN_WARNING):].strip() for line in f if TOKEN_WARNING in line]


@pytest.mark.parametrize("rule,authenticators,expected", [
    ("required;RRQ,URQ,ARQ,BRQ,DRQ", None, {"CAT": "URQ,BRQ,DRQ"}),
    ("required;RRQ,URQ,ARQ,BRQ,DRQ", "MD5,H.235.1", {}),
    ("required;RRQ,ARQ", None, {}),
    ("required;RRQ,ARQ,Connect", "CAT,MD5", {"CAT": "CONNECT", "MD5": "CONNECT"}),
    ("required", "MD5", {"MD5": "LRQ,IRQ,RAI,CONNECT,"}),	# a bare 'required' checks all messages
], ids=["md5-rule-default", "md5-rule-no-cat", "rrq-arq", "connect", "bare-required"])
def test_token_coverage_warning(start_gk, workdir, rule, authenticators, expected):
    """the config check warns when SimplePasswordAuth checks messages an enabled authenticator (CAT, MD5)
    never puts a token into, and suggests disabling it with Authenticators="""
    config = {"Gatekeeper::Auth": {"SimplePasswordAuth": rule}}
    if authenticators:
        config["Gatekeeper::Main"] = {"Authenticators": authenticators}
    gk = start_gk(config, users={"alice": "secret"})
    warnings = token_warnings(gk)
    assert len(warnings) == len(expected), warnings
    for token, messages in expected.items():
        found = [w for w in warnings if " but %s tokens " % token in w]
        assert found, (token, warnings)
        assert found[0].startswith(TOKEN_WARNING + messages), found[0]
        assert "Authenticators=" in found[0], found[0]


@pytest.mark.parametrize("tokens", list(TOKENS))
@pytest.mark.parametrize("compare_case,registers", [
    pytest.param("1", False, id="case-sensitive"),
    pytest.param("0", True, id="case-insensitive", marks=pytest.mark.xfail(strict=True, reason=(
        "the config lookup of the password ignores case and finds 'alice', but SimplePasswordAuth decodes it with the "
        "alias as sent ('Alice'), which fails ('Failed to decode config password'); with CompareAliasCase=1 'Alice' is "
        "rejected only because of that"))),
])
def test_password_alias_case(start_gk, workdir, tokens, compare_case, registers):
    """the password configured for 'alice' is only used for an endpoint 'Alice' with CompareAliasCase=0"""
    auth_config, h2351 = TOKENS[tokens]
    gk = start_gk(auth_config(), {"Gatekeeper::Main": {"CompareAliasCase": compare_case}}, users={"alice": "secret"})
    result = Endpoint(workdir, "pub1", "Alice", password="secret", h2351=h2351).start(duration=1, timeout=5).wait()
    assert result["registered"] == registers, result
