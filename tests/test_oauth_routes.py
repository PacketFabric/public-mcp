import logging
from urllib.parse import parse_qs, urlsplit

import pytest
import respx
from mcp.server.auth.provider import AuthorizationParams
from starlette.applications import Starlette
from starlette.testclient import TestClient

from packetfabric_mcp.oauth.routes import oauth_routes

REDIRECT = "http://127.0.0.1:5555/cb"
PORTAL = "https://portal.example.net"
API_KEY = "api-user-key"


@pytest.fixture
def app(provider, cfg):
    return Starlette(routes=oauth_routes(provider, cfg))


@pytest.fixture
def http(app):
    return TestClient(app)


def meta(**kw):
    kw.setdefault("redirect_uris", [REDIRECT])
    kw.setdefault("client_name", "Test App")
    kw.setdefault("token_endpoint_auth_method", "none")
    return kw


async def pending_request(provider):
    from mcp.shared.auth import OAuthClientMetadata
    from pydantic import AnyUrl

    client = await provider.create_client(OAuthClientMetadata(**meta()))
    url = await provider.authorize(
        client,
        AuthorizationParams(
            state="xyz",
            scopes=None,
            code_challenge="challenge",
            redirect_uri=AnyUrl(REDIRECT),
            redirect_uri_provided_explicitly=True,
            resource="https://mcp.example.net/mcp",
        ),
    )
    return parse_qs(urlsplit(url).query)["request"][0]


def callback(http, body, origin=PORTAL, **kw):
    headers = {"Origin": origin} if origin else {}
    return http.post("/oauth/callback", json=body, headers=headers, **kw)


def test_register_rejects_unknown_redirect(http):
    r = http.post("/register", json=meta(redirect_uris=["https://evil.example/cb"]))
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"
    assert r.headers["cache-control"] == "no-store"


def test_register_ok(http):
    r = http.post("/register", json=meta())
    assert r.status_code == 201
    body = r.json()
    assert body["client_id"].startswith("pfmcp_c_")
    assert "client_secret" not in body
    assert r.headers["access-control-allow-origin"] == "*"
    assert r.headers["cache-control"] == "no-store"


def test_register_confidential_client_gets_secret_and_expiry(http):
    r = http.post("/register", json=meta(token_endpoint_auth_method="client_secret_basic"))
    assert r.status_code == 201
    assert r.json()["client_secret"]
    assert r.json()["client_secret_expires_at"] == 0
    assert r.json()["client_id_issued_at"] > 0


def test_register_bad_json(http):
    r = http.post("/register", content=b"{nope", headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_client_metadata"


@pytest.mark.parametrize(
    "extra",
    [
        {"token_endpoint_auth_method": "private_key_jwt"},
        {"grant_types": ["refresh_token"]},
        {"grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"]},
        {"response_types": ["token"]},
    ],
)
def test_register_mirrors_sdk_metadata_checks(http, extra):
    r = http.post("/register", json=meta(**extra))
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_client_metadata"


def test_register_preflight(http):
    r = http.options("/register", headers={"Origin": "https://app.example", "Access-Control-Request-Method": "POST"})
    assert r.status_code == 204
    assert r.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in r.headers


async def test_request_cors_only_for_portal(http, provider):
    token = await pending_request(provider)
    ok = http.get("/oauth/request", params={"request": token}, headers={"Origin": "https://acme.portal.example.net"})
    assert ok.status_code == 200
    assert ok.headers["access-control-allow-origin"] == "https://acme.portal.example.net"
    assert ok.headers["vary"] == "Origin"
    assert ok.headers["cache-control"] == "no-store"
    assert "access-control-allow-credentials" not in ok.headers
    assert ok.json()["redirect_host"]
    foreign = http.get("/oauth/request", params={"request": token}, headers={"Origin": "https://evil.example"})
    assert foreign.status_code == 200
    assert "access-control-allow-origin" not in foreign.headers


def test_request_garbage_token(http):
    r = http.get("/oauth/request", params={"request": "junk"})
    assert r.status_code == 400
    assert r.json() == {"error": "invalid_request"}
    assert http.get("/oauth/request").status_code == 400


def test_preflight_allowed_and_disallowed(http):
    ok = http.options("/oauth/callback", headers={"Origin": PORTAL, "Access-Control-Request-Method": "POST"})
    assert ok.status_code == 204
    assert ok.headers["access-control-allow-origin"] == PORTAL
    assert ok.headers["access-control-allow-methods"] == "GET, POST, OPTIONS"
    assert ok.headers["access-control-allow-headers"] == "Content-Type"
    assert "access-control-allow-credentials" not in ok.headers
    bad = http.options("/oauth/callback", headers={"Origin": "https://evil.example"})
    assert bad.status_code == 204
    assert "access-control-allow-origin" not in bad.headers


@respx.mock
def test_callback_rejects_foreign_origin(http):
    r = callback(http, {"request": "x", "api_key": API_KEY, "key_uuid": "u1"}, origin="https://evil.example")
    assert r.status_code == 403
    assert r.json() == {"error": "forbidden_origin"}
    assert "access-control-allow-origin" not in r.headers
    assert len(respx.calls) == 0


def test_callback_rejects_missing_origin(http):
    r = callback(http, {"request": "x", "api_key": API_KEY, "key_uuid": "u1"}, origin=None)
    assert r.status_code == 403


def test_callback_origin_checked_before_body(http):
    r = http.post(
        "/oauth/callback", content=b"x" * 100_000, headers={"Origin": "https://evil.example", "Content-Type": "text/plain"}
    )
    assert r.status_code == 403


async def test_callback_ok(http, provider):
    token = await pending_request(provider)
    r = callback(http, {"request": token, "api_key": API_KEY, "key_uuid": "u1"})
    assert r.status_code == 200
    assert r.json()["redirect_to"].startswith(f"{REDIRECT}?code=pfmcp_code_")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["access-control-allow-origin"] == PORTAL


async def test_callback_deny(http, provider):
    token = await pending_request(provider)
    r = callback(http, {"request": token, "error": "access_denied"})
    assert r.status_code == 200
    assert "error=access_denied" in r.json()["redirect_to"]


def test_callback_garbage_request(http):
    r = callback(http, {"request": "junk", "api_key": API_KEY, "key_uuid": "u1"})
    assert r.status_code == 400
    assert r.json() == {"error": "invalid_request"}


async def test_callback_rejects_malformed_bodies(http, provider):
    token = await pending_request(provider)
    bad_bodies = [
        {"api_key": API_KEY, "key_uuid": "u1"},
        {"request": "", "api_key": API_KEY, "key_uuid": "u1"},
        {"request": 5, "api_key": API_KEY, "key_uuid": "u1"},
        {"request": token},
        {"request": token, "api_key": API_KEY},
        {"request": token, "key_uuid": "u1"},
        {"request": token, "api_key": "", "key_uuid": "u1"},
        {"request": token, "api_key": 7, "key_uuid": "u1"},
        {"request": token, "api_key": API_KEY, "key_uuid": "u1", "error": "access_denied"},
        {"request": token, "api_key": API_KEY, "key_uuid": "u1", "error": "server_error"},
        {"request": token, "error": "server_error"},
        {"request": token, "error": "access_denied", "api_key": API_KEY},
        {"request": token, "error": "access_denied", "key_uuid": "u1"},
        [token],
        "text",
    ]
    for body in bad_bodies:
        r = callback(http, body)
        assert r.status_code == 400, body
        assert r.json() == {"error": "invalid_request"}, body
        assert API_KEY not in r.text


def test_callback_rejects_non_json(http):
    for content_type, content in [
        ("text/plain", b'{"request": "x"}'),
        ("application/x-www-form-urlencoded", b"request=x&api_key=k&key_uuid=u"),
        ("application/json", b"{not json"),
        ("application/json", b"\xff\xfe"),
    ]:
        r = http.post("/oauth/callback", content=content, headers={"Origin": PORTAL, "Content-Type": content_type})
        assert r.status_code == 400, content_type
        assert r.json() == {"error": "invalid_request"}


def test_callback_body_cap(http):
    big = {"request": "x" * 20_000, "api_key": API_KEY, "key_uuid": "u1"}
    r = callback(http, big)
    assert r.status_code == 413
    assert r.headers["cache-control"] == "no-store"
    chunked = http.post(
        "/oauth/callback",
        content=iter([b'{"request": "', b"x" * 20_000, b'"}']),
        headers={"Origin": PORTAL, "Content-Type": "application/json"},
    )
    assert chunked.status_code == 413


def test_callback_get_not_allowed(http):
    assert http.get("/oauth/callback", headers={"Origin": PORTAL}).status_code == 405


async def test_no_key_in_responses_or_logs(http, provider, caplog):
    caplog.set_level(logging.DEBUG)
    token = await pending_request(provider)
    bodies = [callback(http, {"request": token, "api_key": API_KEY, "key_uuid": "u1"}).text]
    bodies.append(callback(http, {"request": "junk", "api_key": API_KEY, "key_uuid": "u1"}).text)
    bodies.append(callback(http, {"request": token, "api_key": API_KEY}).text)
    bodies.append(callback(http, {"request": token, "api_key": API_KEY, "key_uuid": "u1"}, origin="https://evil.example").text)
    assert API_KEY not in caplog.text
    assert all(API_KEY not in b for b in bodies)


def test_register_preflight_allows_protocol_version_header(http):
    r = http.options(
        "/register",
        headers={
            "Origin": "https://inspector.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "mcp-protocol-version, content-type",
        },
    )
    assert r.status_code == 204
    allowed = [h.strip().lower() for h in r.headers["access-control-allow-headers"].split(",")]
    assert {"mcp-protocol-version", "content-type", "accept"} <= set(allowed)
    assert r.headers["access-control-allow-origin"] == "*"
    assert r.headers["cache-control"] == "no-store"
