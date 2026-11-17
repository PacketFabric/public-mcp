import pytest
from cryptography.fernet import Fernet

from packetfabric_mcp.oauth.seal import (
    PREFIXES, TOKEN_PREFIX, Sealer, clean_bearer, is_access_token, is_sign_in_artifact,
)

K1, K2 = Fernet.generate_key().decode(), Fernet.generate_key().decode()


def test_roundtrip_and_prefix():
    s = Sealer([K1])
    t = s.seal("access", {"pf_key": "api-x"}, expires_at=2_000_000_000)
    assert t.startswith("pfmcp_at_") and is_access_token(t)
    assert s.unseal("access", t, now=1_000) == {"pf_key": "api-x"}


def test_kind_cannot_be_swapped():
    s = Sealer([K1])
    code = s.seal("code", {"x": 1}, expires_at=None)
    assert s.unseal("access", code) is None
    forged = "pfmcp_at_" + code.removeprefix("pfmcp_code_")
    assert s.unseal("access", forged) is None


def test_tampered_and_expired():
    s = Sealer([K1])
    t = s.seal("request", {"a": 1}, expires_at=100)
    assert s.unseal("request", t[:-2] + ("A" if t[-2] != "A" else "B") + t[-1], now=1) is None
    assert s.unseal("request", t, now=100) is None
    assert s.unseal("request", t, now=99) == {"a": 1}


def test_rotation():
    old = Sealer([K1]).seal("client", {"n": "c"}, expires_at=None)
    assert Sealer([K2, K1]).unseal("client", old) == {"n": "c"}
    assert Sealer([K2]).unseal("client", old) is None


def test_client_secret_is_stable_per_key():
    assert Sealer([K1]).client_secret("c1") == Sealer([K1, K2]).client_secret("c1")
    assert Sealer([K1]).client_secret("c1") != Sealer([K2]).client_secret("c1")


def test_unseal_never_raises_on_garbage():
    s = Sealer([K1])
    for junk in ["", "pfmcp_at_", "pfmcp_at_!!!", "nope", None, 5, b"pfmcp_at_x"]:
        assert s.unseal("access", junk) is None


def test_unseal_rejects_malformed_bodies():
    from cryptography.fernet import Fernet as F

    f = F(K1)
    for body in [b"not json", b"[1]", b'{"k":"access"}', b'{"p":{}}', b'{"k":"access","p":[1]}']:
        assert Sealer([K1]).unseal("access", "pfmcp_at_" + f.encrypt(body).decode()) is None


def test_empty_secrets_rejected():
    with pytest.raises(ValueError):
        Sealer([])


def test_every_prefix_is_in_the_sign_in_namespace():
    assert TOKEN_PREFIX == "pfmcp_"
    assert all(p.startswith(TOKEN_PREFIX) for p in PREFIXES.values())


@pytest.mark.parametrize(
    "value,cleaned",
    [
        ("abc", "abc"),
        ("  abc\t", "abc"),
        ("", None),
        ("   ", None),
        ("x pfmcp_at_y", None),
        ("a\tb", None),
        ("a\x00b", None),
        ("a\x7fb", None),
        ("a\x85b", None),
    ],
)
def test_clean_bearer(value, cleaned):
    assert clean_bearer(value) == cleaned


def test_is_sign_in_artifact():
    assert is_sign_in_artifact("pfmcp_at_x") and is_sign_in_artifact("pfmcp_code_x") and is_sign_in_artifact("pfmcp_")
    assert not is_sign_in_artifact("api-key") and not is_sign_in_artifact("xpfmcp_at_")
