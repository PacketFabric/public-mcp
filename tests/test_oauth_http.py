import base64
import hashlib
import inspect
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from cryptography.fernet import Fernet

from conftest import serve

MCP_URL = "https://mcp.example.net"
PORTAL = "https://portal.example.net"
PF = "https://api.packetfabric.com"
REDIRECT = "http://127.0.0.1:5555/cb"
HDRS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
PROTO = {"MCP-Protocol-Version": "2025-11-25"}
INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
}  # fmt: skip
CALL = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "pf_get_account", "arguments": {}}}
OAUTH_ENV = ("PF_OAUTH_SECRET", "PF_PORTAL_URL", "PF_PORTAL_ORIGINS", "PF_OAUTH_ALLOWED_REDIRECTS",
             "PF_OAUTH_KEY_TTL_SECONDS", "PF_PUBLIC_URL")  # fmt: skip


@pytest.fixture
def base_env(monkeypatch):
    monkeypatch.setenv("PF_TOKEN", "operator-key")  # must NOT be used by the hosted app
    for name in (*OAUTH_ENV, "PF_API_URL", "PF_ON_BEHALF", "PF_HTTP_USE_SERVER_CREDENTIALS"):
        monkeypatch.delenv(name, raising=False)
    from packetfabric_mcp import server

    server._client = None
    yield monkeypatch
    server._client = None


@pytest.fixture
def oauth_env(base_env):
    base_env.setenv("PF_OAUTH_SECRET", Fernet.generate_key().decode())
    base_env.setenv("PF_PORTAL_URL", PORTAL)
    base_env.setenv("PF_PORTAL_ORIGINS", "https://portal.example.net, https://*.portal.example.net")
    return base_env


@pytest.fixture
def oauth_app(oauth_env):
    from packetfabric_mcp.http_app import build_app

    return build_app(public_url=MCP_URL)


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


async def register(http):
    r = await http.post(
        "/register", json={"redirect_uris": [REDIRECT], "client_name": "Test", "token_endpoint_auth_method": "none"}
    )
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


async def authorize(http, client_id, challenge):
    return await http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "resource": f"{MCP_URL}/mcp",
        },
    )


async def test_keyless_mcp_gets_401_with_resource_metadata(oauth_app):
    async with serve(oauth_app) as http:
        r = await http.post("/mcp", json=INIT, headers=HDRS)
        assert r.status_code == 401
        assert (
            f'resource_metadata="{MCP_URL}/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]
        )


async def test_metadata_documents(oauth_app):
    async with serve(oauth_app) as http:
        r = await http.get("/.well-known/oauth-protected-resource/mcp")
        assert r.status_code == 200
        resource = r.json()
        assert resource["resource"] == f"{MCP_URL}/mcp"
        assert resource["authorization_servers"][0].startswith(MCP_URL)

        r = await http.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        metadata = r.json()
        # Must equal the `iss` the provider puts on redirects, or clients reject the sign-in.
        assert metadata["issuer"] == "https://mcp.example.net"
        assert metadata["registration_endpoint"] == f"{MCP_URL}/register"
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert metadata["revocation_endpoint"] == f"{MCP_URL}/revoke"


def test_registration_settings_carry_no_scopes(cfg):
    from packetfabric_mcp.http_app import _auth_settings

    options = _auth_settings(cfg).client_registration_options
    assert options.enabled and options.valid_scopes is None and options.default_scopes is None


async def test_register_route_is_ours(oauth_app):
    async with serve(oauth_app) as http:
        assert (await register(http)).startswith("pfmcp_c_")


async def test_authorize_redirects_to_portal(oauth_app):
    async with serve(oauth_app) as http:
        client_id = await register(http)
        r = await authorize(http, client_id, pkce()[1])
        assert r.status_code == 302, r.text
        assert r.headers["location"].startswith(f"{PORTAL}/mcp/connect?request=pfmcp_r_")


@respx.mock
async def test_raw_key_still_works_with_oauth_on(oauth_app, respx_mock):
    route = respx_mock.get(f"{PF}/v2/customers/current").mock(return_value=httpx.Response(200, json={"name": "X"}))
    auth = {"Authorization": "Bearer caller-key"}
    async with serve(oauth_app) as http:
        assert (await http.post("/mcp", json=INIT, headers={**HDRS, **auth})).status_code == 200
        r = await http.post("/mcp", json=CALL, headers={**HDRS, **PROTO, **auth})
        assert r.json()["result"]["isError"] is False, r.text
        assert route.calls.last.request.headers["Authorization"] == "Bearer caller-key"


@respx.mock
async def test_on_behalf_still_forwarded(oauth_app, respx_mock):
    route = respx_mock.get(f"{PF}/v2/customers/current").mock(return_value=httpx.Response(200, json={"name": "X"}))
    auth = {"Authorization": "Bearer caller-key", "On-Behalf": "cust-1"}
    async with serve(oauth_app) as http:
        assert (await http.post("/mcp", json=INIT, headers={**HDRS, **auth})).status_code == 200
        r = await http.post("/mcp", json=CALL, headers={**HDRS, **PROTO, **auth})
        assert r.json()["result"]["isError"] is False, r.text
        sent = route.calls.last.request.headers
        assert sent["Authorization"] == "Bearer caller-key"
        assert sent["On-Behalf"] == "cust-1"


@respx.mock
async def test_signed_in_token_calls_api_with_users_key(oauth_app, respx_mock):
    route = respx_mock.get(f"{PF}/v2/customers/current").mock(return_value=httpx.Response(200, json={"name": "X"}))
    async with serve(oauth_app) as http:
        client_id = await register(http)
        verifier, challenge = pkce()
        location = (await authorize(http, client_id, challenge)).headers["location"]
        request = parse_qs(urlsplit(location).query)["request"][0]
        r = await http.post(
            "/oauth/callback",
            json={"request": request, "api_key": "user-minted-key", "key_uuid": "key-1"},
            headers={"Origin": PORTAL},
        )
        assert r.status_code == 200, r.text
        redirect = parse_qs(urlsplit(r.json()["redirect_to"]).query)
        assert redirect["iss"] == ["https://mcp.example.net"]
        r = await http.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": redirect["code"][0],
                "redirect_uri": REDIRECT,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": f"{MCP_URL}/mcp",
            },
        )
        assert r.status_code == 200, r.text
        sealed = r.json()["access_token"]
        assert sealed.startswith("pfmcp_at_")

        auth = {"Authorization": f"Bearer {sealed}", "On-Behalf": "cust-1"}
        assert (await http.post("/mcp", json=INIT, headers={**HDRS, **auth})).status_code == 200
        r = await http.post("/mcp", json=CALL, headers={**HDRS, **PROTO, **auth})
        assert r.json()["result"]["isError"] is False, r.text
        sent = route.calls.last.request.headers
        assert sent["Authorization"] == "Bearer user-minted-key"  # never the sealed token itself
        assert sent["On-Behalf"] == "cust-1"


async def test_bad_signed_in_token_gets_401(oauth_app):
    async with serve(oauth_app) as http:
        r = await http.post("/mcp", json=INIT, headers={**HDRS, "Authorization": "Bearer pfmcp_at_forged"})
        assert r.status_code == 401


@pytest.mark.parametrize(
    "header", ["Bearer  pfmcp_at_gAAAAABforgedButWellFormed", "Bearer  pfmcp_code_x", "Bearer \tpfmcp_at_x"]
)
async def test_padded_sign_in_tokens_get_401_and_never_reach_packetfabric(oauth_app, respx_mock, header):
    async with serve(oauth_app) as http:
        for body in (INIT, CALL):
            r = await http.post("/mcp", json=body, headers={**HDRS, **PROTO, "Authorization": header})
            assert r.status_code == 401
            assert 'resource_metadata="' in r.headers["www-authenticate"]
    assert not respx_mock.calls


@respx.mock
async def test_padded_raw_key_is_sent_stripped(oauth_app, respx_mock):
    route = respx_mock.get(f"{PF}/v2/customers/current").mock(return_value=httpx.Response(200, json={"name": "X"}))
    auth = {"Authorization": "Bearer  caller-key"}
    async with serve(oauth_app) as http:
        assert (await http.post("/mcp", json=INIT, headers={**HDRS, **auth})).status_code == 200
        r = await http.post("/mcp", json=CALL, headers={**HDRS, **PROTO, **auth})
        assert r.json()["result"]["isError"] is False, r.text
        assert route.calls.last.request.headers["Authorization"] == "Bearer caller-key"


async def test_oauth_off_is_unchanged(base_env):
    from packetfabric_mcp.http_app import build_app

    async with serve(build_app(public_url=MCP_URL)) as http:
        assert (await http.get("/.well-known/oauth-authorization-server")).status_code == 404
        assert (await http.post("/mcp", json=INIT, headers=HDRS)).status_code == 200


def test_missing_public_url_fails_fast(oauth_env):
    from packetfabric_mcp.http_app import build_app

    with pytest.raises(ValueError):
        build_app(public_url=None)


def test_sdk_contract():
    from packetfabric_mcp import server

    assert "_lowlevel_server" in vars(server.mcp)
    params = inspect.signature(server.mcp._lowlevel_server.streamable_http_app).parameters
    assert {"auth", "token_verifier", "auth_server_provider", "custom_starlette_routes", "debug"} <= params.keys()
    assert isinstance(server.mcp._custom_starlette_routes, list)
    assert isinstance(server.mcp.settings.debug, bool)


def test_oauth_app_keeps_mcpserver_routes_and_debug(oauth_env, monkeypatch):
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    from packetfabric_mcp import server
    from packetfabric_mcp.http_app import build_app

    extra = Route("/extra-probe", lambda request: PlainTextResponse("ok"))
    monkeypatch.setattr(server.mcp, "_custom_starlette_routes", [extra])
    monkeypatch.setattr(server.mcp.settings, "debug", True)
    app = build_app(public_url=MCP_URL)
    assert extra in app.router.routes
    assert app.debug is True
