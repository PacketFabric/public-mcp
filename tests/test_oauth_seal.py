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


def test_client_secret_survives_rotation():
    client_id = Sealer([K1]).seal("client", {"n": "c"}, expires_at=None)
    secret = Sealer([K1]).client_secret(client_id)
    assert secret
    assert Sealer([K2, K1]).client_secret(client_id) == secret
    assert Sealer([K2]).client_secret(client_id) is None


def test_client_secret_uses_the_key_that_sealed_the_client():
    a = Sealer([K1]).seal("client", {"n": "a"}, expires_at=None)
    b = Sealer([K2]).seal("client", {"n": "b"}, expires_at=None)
    both = Sealer([K2, K1])
    assert both.client_secret(a) == Sealer([K1]).client_secret(a)
    assert both.client_secret(b) == Sealer([K2]).client_secret(b)
    assert both.client_secret(a) != both.client_secret(b)


def test_client_secret_is_domain_separated():
    import base64
    import hashlib
    import hmac

    client_id = Sealer([K1]).seal("client", {"n": "c"}, expires_at=None)
    key = base64.urlsafe_b64decode(K1)
    old_style = hmac.new(key, client_id.encode(), hashlib.sha256).hexdigest()
    expected = hmac.new(key, b"client-secret:" + client_id.encode(), hashlib.sha256).hexdigest()
    assert Sealer([K1]).client_secret(client_id) == expected != old_style


@pytest.mark.parametrize("junk", ["", "c1", "pfmcp_c_", "pfmcp_c_garbage", None, 5])
def test_client_secret_none_for_garbage(junk):
    assert Sealer([K1]).client_secret(junk) is None


def test_client_secret_none_for_other_kinds():
    s = Sealer([K1])
    access = s.seal("access", {"n": "c"}, expires_at=None)
    assert s.client_secret(access) is None
    assert s.client_secret("pfmcp_c_" + access.removeprefix("pfmcp_at_")) is None


@pytest.mark.parametrize("exp", ['"9999999999"', "1.5", "true", "[1]", "{}"])
def test_unseal_rejects_non_int_exp(exp):
    from cryptography.fernet import Fernet as F

    body = ('{"k":"access","exp":%s,"p":{}}' % exp).encode()
    assert Sealer([K1]).unseal("access", "pfmcp_at_" + F(K1).encrypt(body).decode(), now=1) is None


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
