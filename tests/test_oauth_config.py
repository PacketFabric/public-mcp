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
    ("vscode://vscode.github-authentication/did-authenticate", True),
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
    assert redirect_display("cursor://anysphere.cursor-mcp/oauth/callback") == "cursor://"

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
    monkeypatch.setenv("PF_OAUTH_KEY_TTL_SECONDS", "60")
    monkeypatch.setenv("PF_PUBLIC_URL", "https://mcp.example.net")
    c = OAuthConfig.from_env(None)
    assert c.portal_origins == DEFAULT_PORTAL_ORIGINS
    assert c.allowed_redirects == DEFAULT_ALLOWED_REDIRECTS
    assert c.key_ttl_seconds == 60

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
        "cursor://",
        "vscode://",
        "vscode-insiders://",
    )


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.com/api/mcp/auth_callback",
        "https://vscode.dev/redirect",
        "vscode-insiders://vscode.github-authentication/did-authenticate",
    ],
)
def test_newly_allowed_redirects(uri):
    assert redirect_allowed(uri, DEFAULT_ALLOWED_REDIRECTS) is True
