import pytest
from packetfabric_mcp.oauth.config import (
    DEFAULT_ALLOWED_REDIRECTS, DEFAULT_PORTAL_ORIGINS, OAuthConfig,
    origin_allowed, redirect_allowed, redirect_display,
)

@pytest.mark.parametrize("origin,ok", [
    ("https://portal.packetfabric.com", True),
    ("https://portal-beta.packetfabric.com", True),
    ("https://acme.portal.packetfabric.com", True),
    ("https://a.b.portal.packetfabric.com", False),
    ("https://portal.packetfabric.com.evil.com", False),
    ("http://portal.packetfabric.com", False),
    ("https://portal.packetfabric.com:8443", False),
    ("https://evilportal.packetfabric.com", False),
    ("https://PORTAL.packetfabric.com", True),
    ("https://portal.packetfabric.com/", False),
    ("https://portal.packetfabric.com/x", False),
    ("https://portal.packetfabric.com?x=1", False),
    ("https://user@portal.packetfabric.com", False),
    (None, False), ("null", False), ("", False),
])
def test_origin_allowed(origin, ok):
    assert origin_allowed(origin, DEFAULT_PORTAL_ORIGINS) is ok

def test_origin_exact_port():
    assert origin_allowed("https://demo.packetfabric.net:3000", ["https://demo.packetfabric.net:3000"])
    assert not origin_allowed("https://demo.packetfabric.net", ["https://demo.packetfabric.net:3000"])

@pytest.mark.parametrize("uri,ok", [
    ("https://claude.ai/api/mcp/auth_callback", True),
    ("https://chatgpt.com/connector_platform_oauth_redirect", True),
    ("cursor://anysphere.cursor-mcp/oauth/callback", True),
    ("vscode://vscode.github-authentication/did-authenticate", False),
    ("http://localhost:51234/callback", True),
    ("http://127.0.0.1/cb", True),
    ("http://[::1]:9000/cb", True),
    ("http://localhost.evil.com/cb", False),
    ("https://claude.ai/api/mcp/auth_callback/../x", False),
    ("https://claude.ai/api/mcp/auth_callbackx", False),
    ("https://claude.ai/api/mcp/auth_callback#frag", False),
    ("http://localhost/cb#frag", False),
    ("https://evil.com/?r=https://claude.ai/api/mcp/auth_callback", False),
    ("javascript:alert(1)", False),
    ("https://evil.example/cb", False),
])
def test_redirect_allowed(uri, ok):
    assert redirect_allowed(uri, DEFAULT_ALLOWED_REDIRECTS) is ok

def test_redirect_display():
    assert redirect_display("http://127.0.0.1:5555/cb") == "127.0.0.1:5555"
    assert redirect_display("https://claude.ai/api/mcp/auth_callback") == "claude.ai"
    assert redirect_display("cursor://anysphere.cursor-mcp/oauth/callback") == "cursor://anysphere.cursor-mcp"
    assert redirect_display("cursor://anysphere.cursor-mcp:9/x") == "cursor://anysphere.cursor-mcp:9"
    assert redirect_display("myapp:/callback") == "myapp:"

def test_from_env_disabled_unless_both_set(monkeypatch):
    monkeypatch.delenv("PF_OAUTH_SECRET", raising=False)
    monkeypatch.setenv("PF_PORTAL_URL", "https://portal.example.net")
    assert OAuthConfig.from_env("https://mcp.example.net") is None

def test_from_env_requires_public_url(monkeypatch):
    monkeypatch.setenv("PF_OAUTH_SECRET", "k")
    monkeypatch.setenv("PF_PORTAL_URL", "https://portal.example.net")
    monkeypatch.delenv("PF_PUBLIC_URL", raising=False)
    with pytest.raises(ValueError, match="PF_PUBLIC_URL is required"):
        OAuthConfig.from_env(None)

def test_from_env_parses_lists_and_defaults(monkeypatch):
    monkeypatch.setenv("PF_OAUTH_SECRET", "new, old")
    monkeypatch.setenv("PF_PORTAL_URL", "https://portal.example.net/")
    monkeypatch.setenv("PF_PORTAL_ORIGINS", "https://portal.example.net, https://*.portal.example.net")
    monkeypatch.delenv("PF_OAUTH_ALLOWED_REDIRECTS", raising=False)
    monkeypatch.delenv("PF_OAUTH_KEY_TTL_SECONDS", raising=False)
    c = OAuthConfig.from_env("https://mcp.example.net/")
    assert c.secrets == ("new", "old")
    assert c.portal_url == "https://portal.example.net"
    assert c.resource_url == "https://mcp.example.net/mcp"
    assert c.portal_origins == ("https://portal.example.net", "https://*.portal.example.net")
    assert c.allowed_redirects == DEFAULT_ALLOWED_REDIRECTS
    assert c.key_ttl_seconds == 2_592_000

def test_from_env_empty_lists_use_defaults(monkeypatch):
    monkeypatch.setenv("PF_OAUTH_SECRET", "k")
    monkeypatch.setenv("PF_PORTAL_URL", "https://portal.example.net")
    monkeypatch.setenv("PF_PORTAL_ORIGINS", " , ")
    monkeypatch.setenv("PF_OAUTH_ALLOWED_REDIRECTS", "")
    monkeypatch.setenv("PF_OAUTH_KEY_TTL_SECONDS", "600")
    monkeypatch.setenv("PF_PUBLIC_URL", "https://mcp.example.net")
    c = OAuthConfig.from_env(None)
    assert c.portal_origins == DEFAULT_PORTAL_ORIGINS
    assert c.allowed_redirects == DEFAULT_ALLOWED_REDIRECTS
    assert c.key_ttl_seconds == 600


@pytest.fixture
def enabled_env(monkeypatch):
    monkeypatch.setenv("PF_OAUTH_SECRET", "k")
    monkeypatch.setenv("PF_PORTAL_URL", "https://portal.example.net")
    monkeypatch.setenv("PF_PUBLIC_URL", "https://mcp.example.net")
    monkeypatch.delenv("PF_OAUTH_KEY_TTL_SECONDS", raising=False)
    return monkeypatch


@pytest.mark.parametrize(
    "raw,normalised",
    [
        ("https://MCP.Example.net:443/", "https://mcp.example.net"),
        ("http://mcp.example.net:80", "http://mcp.example.net"),
        ("https://mcp.example.net:8443/", "https://mcp.example.net:8443"),
        ("https://mcp.example.net/base/", "https://mcp.example.net/base"),
    ],
)
def test_public_url_is_normalised(enabled_env, raw, normalised):
    enabled_env.setenv("PF_PUBLIC_URL", raw)
    c = OAuthConfig.from_env(None)
    assert c.public_url == normalised
    assert c.resource_url == normalised + "/mcp"


@pytest.mark.parametrize("ttl", ["30", "299", "abc", "1.5e6", "-300"])
def test_key_ttl_must_be_an_integer_of_at_least_300(enabled_env, ttl):
    enabled_env.setenv("PF_OAUTH_KEY_TTL_SECONDS", ttl)
    with pytest.raises(ValueError, match="PF_OAUTH_KEY_TTL_SECONDS must be an integer of at least 300"):
        OAuthConfig.from_env(None)


def test_key_ttl_minimum_is_accepted(enabled_env):
    enabled_env.setenv("PF_OAUTH_KEY_TTL_SECONDS", "300")
    assert OAuthConfig.from_env(None).key_ttl_seconds == 300

@pytest.mark.parametrize("uri", [
    "http://evil.com\\@localhost/cb",
    "http://evil.com@localhost/cb",
    "http://user:pw@127.0.0.1/cb",
    "http://localhost/cb\r\nX: y",
    "http://local\nhost/cb",
    " http://localhost/cb",
    "http://localhost/cb\t",
    "http://localhost/c\x00b",
    "http://localhost/cbé",
    "https://claude.ai/api/mcp/auth_callback\n",
    "cursor://x@anysphere.cursor-mcp/cb",
])
def test_redirect_refuses_lookalikes(uri):
    assert redirect_allowed(uri, DEFAULT_ALLOWED_REDIRECTS) is False

@pytest.mark.parametrize("origin", [
    "https://portal.packetfabric.com\n",
    "  https://portal.packetfabric.com",
    "https://portal.packetfabric.com\t",
    "https://portal.packetfabric.com\\@evil.com",
    "https://acmeK.portal.packetfabric.com",
])
def test_origin_refuses_lookalikes(origin):
    assert origin_allowed(origin, DEFAULT_PORTAL_ORIGINS) is False


def test_default_allowed_redirects_exact():
    assert DEFAULT_ALLOWED_REDIRECTS == (
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://vscode.dev/redirect",
        "cursor://anysphere.cursor-mcp/oauth/callback",
    )


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.com/api/mcp/auth_callback",
        "https://vscode.dev/redirect",
        "cursor://anysphere.cursor-mcp/oauth/callback",
    ],
)
def test_newly_allowed_redirects(uri):
    assert redirect_allowed(uri, DEFAULT_ALLOWED_REDIRECTS) is True


@pytest.mark.parametrize(
    "uri",
    [
        "cursor://anysphere.cursor-deeplink/mcp/install?x=1",
        "vscode://vscode.git/clone?url=x",
        "vscode-insiders://a/b",
        "cursor://anysphere.cursor-mcp/oauth/callback?x=1",
        "CURSOR://anysphere.cursor-mcp/oauth/callback",
    ],
)
def test_deeplinks_must_match_exactly(uri):
    assert redirect_allowed(uri, DEFAULT_ALLOWED_REDIRECTS) is False


def test_scheme_only_entry_no_longer_matches_the_scheme():
    assert redirect_allowed("cursor://anything/x", ["cursor://"]) is False
