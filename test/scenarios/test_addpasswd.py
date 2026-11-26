"""addpasswd: the entries it writes are accepted by GnuGk, for SimplePasswordAuth and the status port."""

import base64

import pytest

from harness import gnugk
from harness.endpoint import Endpoint
from harness.gnugk import StatusSession, status_password, traditional_password

TOKENS = {
    "md5": (gnugk.md5_config, False),
    "h2351": (gnugk.h2351_setup_config, True),
}

# where the padding byte (KeyFilled) is set: the auth section, [Gatekeeper::Main] or nowhere (0)
KEY_FILLED = {
    "section": {},
    "global": {"SimplePasswordAuth": {"KeyFilled": None}, "Gatekeeper::Main": {"KeyFilled": "42"}},
    "none": {"SimplePasswordAuth": {"KeyFilled": None}},
}


def describe_params(params):
    """description of the parameters, shown by --describe"""
    parts = []
    if "tokens" in params:
        parts.append({"md5": "MD5 tokens", "h2351": "H.235.1 tokens"}[params["tokens"]])
    if "key_filled" in params:
        parts.append("KeyFilled " + {"section": "in [SimplePasswordAuth]", "global": "in [Gatekeeper::Main]",
                                     "none": "not set"}[params["key_filled"]])
    if "entry_format" in params:
        parts.append({"pbkdf2": "PBKDF2 entry", "traditional": "traditional entry"}[params["entry_format"]])
    return "; ".join(parts)


def config_entries(config_file, section):
    """the key=value lines of a section in the config file"""
    entries, current = [], None
    with open(config_file) as f:
        for line in f:
            line = line.strip()
            if line.startswith("["):
                current = line[1:-1]
            elif current == section and "=" in line:
                entries.append(tuple(line.split("=", 1)))
    return entries


@pytest.mark.parametrize("tokens", list(TOKENS))
@pytest.mark.parametrize("key_filled", list(KEY_FILLED))
def test_simple_password_auth_entry(start_gk, workdir, tokens, key_filled):
    """addpasswd writes an encrypted entry (base64, whole TEA blocks) with the padding byte from the section,
    from [Gatekeeper::Main] or 0, and GnuGk reads it with the same one: the endpoint registers"""
    auth_config, h2351 = TOKENS[tokens]
    gk = start_gk(auth_config(), KEY_FILLED[key_filled], users={"alice": "secret"})
    values = [value for key, value in config_entries(gk.config_file, "SimplePasswordAuth") if key == "alice"]
    assert len(values) == 1, values
    raw = base64.b64decode(values[0], validate=True)
    assert raw and len(raw) % 8 == 0, values[0]
    result = Endpoint(workdir, "pub1", "alice", password="secret", h2351=h2351).start(duration=1).wait()
    assert result["registered"]


@pytest.mark.parametrize("tokens", list(TOKENS))
def test_replace_entry_with_other_case(start_gk, workdir, tokens):
    """running addpasswd again for 'Alice' replaces the entry of 'alice' and stores the new spelling: 'Alice'
    registers with the new password, 'alice' no longer with the old one"""
    auth_config, h2351 = TOKENS[tokens]
    users = {"alice": "old", "Alice": "secret"}	# addpasswd runs in this order
    gk = start_gk(auth_config(), users=users)
    keys = [key for key, _ in config_entries(gk.config_file, "SimplePasswordAuth") if key.lower() == "alice"]
    assert keys == ["Alice"], keys
    result = Endpoint(workdir, "pub1", "Alice", password="secret", h2351=h2351).start(duration=1).wait()
    assert result["registered"]
    result = Endpoint(workdir, "pub1", "alice", password="old", h2351=h2351).start(duration=1, timeout=5).wait()
    assert not result["registered"]


@pytest.mark.parametrize("entry_format", ["pbkdf2", "traditional"])
def test_status_port_entry(start_gk, workdir, entry_format):
    """an entry addpasswd writes for the status port user 'GkAdmin' logs in with the right password, but not
    as 'gkadmin': for [GkStatus::Auth] addpasswd writes a PBKDF2 digest, for another section without KeyFilled
    the traditional encrypted format that GnuGk also accepts in [GkStatus::Auth]"""
    if entry_format == "pbkdf2":
        entry = status_password(workdir, "GkAdmin", "secret")
    else:
        entry = traditional_password(workdir, "GkAdmin", "secret")
        assert not entry.startswith("PBKDF2:"), entry
    gk = start_gk({"GkStatus::Auth": {"rule": "password", "GkAdmin": entry, "DelayReject": "0"}})
    session = StatusSession()
    try:
        assert not session.login_accepted("gkadmin", b"secret")
        assert not session.login_accepted("GkAdmin", b"wrong")
        assert session.login_accepted("GkAdmin", b"secret")
    finally:
        session.close()
    assert gk.trace_count("spelling differs from the config") == 1
