import dataclasses
import logging
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError, TokenError
from mcp.shared.auth import OAuthClientMetadata
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.routing import Route

from packetfabric_mcp.client import PFError
from packetfabric_mcp.oauth import provider as provider_mod
from packetfabric_mcp.oauth.provider import (
    InvalidRequest,
    PacketFabricOAuthProvider,
    PFAccessToken,
    PFAuthorizationCode,
)
from packetfabric_mcp.oauth.seal import Sealer

BASE = "https://api.packetfabric.com"
REDIRECT = "http://127.0.0.1:5555/cb"
TTL = 2_592_000


def metadata(**kw):
    kw.setdefault("redirect_uris", [REDIRECT])
    kw.setdefault("client_name", "Test App")
    kw.setdefault("token_endpoint_auth_method", "none")
    return OAuthClientMetadata(**kw)


def params(redirect=REDIRECT, state="xyz", resource="https://mcp.example.net/mcp"):
    return AuthorizationParams(
        state=state,
        scopes=None,
        code_challenge="challenge",
        redirect_uri=AnyUrl(redirect),
        redirect_uri_provided_explicitly=True,
        resource=resource,
    )


def request_token(url):
    return parse_qs(urlsplit(url).query)["request"][0]


async def pending(provider, **kw):
    client = await provider.create_client(metadata(**kw))
    return client, request_token(await provider.authorize(client, params()))


async def issued_code(provider):
    client, req = await pending(provider)
    url = await provider.complete_request(req, api_key="api-user-key", key_uuid="u1")
    return client, parse_qs(urlsplit(url).query)["code"][0]


async def test_create_client_rejects_unknown_redirect(provider):
    with pytest.raises(RegistrationError) as e:
        await provider.create_client(metadata(redirect_uris=["https://evil.example/cb"]))
    assert e.value.error == "invalid_redirect_uri"


async def test_create_client_rejects_if_any_redirect_unknown(provider):
    with pytest.raises(RegistrationError):
        await provider.create_client(metadata(redirect_uris=[REDIRECT, "https://evil.example/cb"]))


async def test_create_and_get_client_roundtrip(provider):
    created = await provider.create_client(metadata())
    assert created.client_id.startswith("pfmcp_c_")
    assert created.client_secret is None
    loaded = await provider.get_client(created.client_id)
    assert loaded.client_name == "Test App"
    assert loaded.client_secret is None
    assert loaded.client_id_issued_at == created.client_id_issued_at
    assert [str(u) for u in loaded.redirect_uris] == [REDIRECT]

    confidential = await provider.create_client(metadata(token_endpoint_auth_method="client_secret_post"))
    assert confidential.client_secret
    assert (await provider.get_client(confidential.client_id)).client_secret == confidential.client_secret


async def test_missing_auth_method_defaults_to_client_secret_post(provider):
    created = await provider.create_client(metadata(token_endpoint_auth_method=None))
    assert created.token_endpoint_auth_method == "client_secret_post"
    assert created.client_secret
    loaded = await provider.get_client(created.client_id)
    assert loaded.token_endpoint_auth_method == "client_secret_post"
    assert loaded.client_secret == created.client_secret


async def test_get_client_garbage_is_none(provider):
    assert await provider.get_client("nope") is None
    assert await provider.get_client("pfmcp_c_garbage") is None


async def test_register_client_not_supported(provider):
    created = await provider.create_client(metadata())
    with pytest.raises(NotImplementedError):
        await provider.register_client(created)


async def test_authorize_rechecks_allowlist(cfg, pf):
    old = "https://old.example/cb"
    before = dataclasses.replace(cfg, allowed_redirects=(*cfg.allowed_redirects, old))
    client = await PacketFabricOAuthProvider(before, Sealer(cfg.secrets), pf).create_client(
        metadata(redirect_uris=[old])
    )
    after = PacketFabricOAuthProvider(cfg, Sealer(cfg.secrets), pf)
    with pytest.raises(AuthorizeError) as e:
        await after.authorize(client, params(redirect=old))
    assert e.value.error == "invalid_request"


async def delisted_client(cfg, pf, redirect_uris):
    before = dataclasses.replace(cfg, allowed_redirects=(*cfg.allowed_redirects, "https://old.example/cb"))
    created = await PacketFabricOAuthProvider(before, Sealer(cfg.secrets), pf).create_client(
        metadata(redirect_uris=redirect_uris)
    )
    return created.client_id


async def test_get_client_drops_delisted_redirects(cfg, pf, provider):
    client_id = await delisted_client(cfg, pf, ["https://old.example/cb", REDIRECT])
    assert [str(u) for u in (await provider.get_client(client_id)).redirect_uris] == [REDIRECT]

    only_delisted = await provider.get_client(await delisted_client(cfg, pf, ["https://old.example/cb"]))
    assert only_delisted is not None
    assert only_delisted.redirect_uris == []


@pytest.mark.parametrize("explicit", [True, False])
async def test_authorize_endpoint_never_redirects_to_delisted_uri(cfg, pf, provider, explicit):
    client_id = await delisted_client(cfg, pf, ["https://old.example/cb"])
    app = Starlette(routes=[Route("/authorize", AuthorizationHandler(provider).handle, methods=["GET"])])
    query = {
        "response_type": "code",
        "client_id": client_id,
        "code_challenge": "c" * 43,
        "code_challenge_method": "S256",
        "state": "s",
    }
    if explicit:
        query["redirect_uri"] = "https://old.example/cb"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.net") as http:
        r = await http.get("/authorize", params=query)
    assert r.status_code == 400
    assert "location" not in r.headers
    assert r.json()["error"] == "invalid_request"


async def test_authorize_redirects_to_portal(provider):
    client = await provider.create_client(metadata())
    url = await provider.authorize(client, params())
    assert url.startswith("https://portal.example.net/mcp/connect?request=pfmcp_r_")


async def access_for_resource(provider, resource):
    client = await provider.create_client(metadata())
    req = request_token(await provider.authorize(client, params(resource=resource)))
    url = await provider.complete_request(req, api_key="api-user-key", key_uuid="u1")
    code = await provider.load_authorization_code(client, parse_qs(urlsplit(url).query)["code"][0])
    token = await provider.exchange_authorization_code(client, code)
    return await provider.load_access_token(token.access_token)


async def test_authorize_defaults_resource(provider):
    assert (await access_for_resource(provider, None)).resource == "https://mcp.example.net/mcp"


@pytest.mark.parametrize("resource", ["https://other.example/mcp", "https://mcp.example.net/other", "not a url"])
async def test_authorize_rejects_foreign_resource(provider, resource):
    client = await provider.create_client(metadata())
    with pytest.raises(AuthorizeError) as e:
        await provider.authorize(client, params(resource=resource))
    assert e.value.error == "invalid_target"


@pytest.mark.parametrize(
    "resource", ["https://mcp.example.net/mcp/", "HTTPS://MCP.Example.NET/mcp", "https://mcp.example.net:443/mcp"]
)
async def test_authorize_accepts_trailing_slash_resource(provider, resource):
    assert (await access_for_resource(provider, resource)).resource == "https://mcp.example.net/mcp"


async def test_describe_request(provider):
    _, req = await pending(provider)
    info = await provider.describe_request(req)
    expires_at = info.pop("expires_at")
    assert info == {"client_name": "Test App", "redirect_host": "127.0.0.1:5555", "key_ttl_seconds": TTL}
    assert abs(expires_at - (time.time() + 600)) <= 2


async def test_describe_request_falls_back_to_redirect_host(provider):
    _, req = await pending(provider, client_name=None)
    assert (await provider.describe_request(req))["client_name"] == "127.0.0.1:5555"


async def test_describe_request_garbage(provider):
    with pytest.raises(InvalidRequest):
        await provider.describe_request("pfmcp_r_garbage")


async def test_complete_then_exchange(provider):
    client, req = await pending(provider)
    url = await provider.complete_request(req, api_key="api-user-key", key_uuid="u1")
    assert url.startswith(REDIRECT + "?")
    assert "code=pfmcp_code_" in url and "state=xyz" in url
    assert "iss=https%3A%2F%2Fmcp.example.net" in url
    assert "api-user-key" not in url
    code = parse_qs(urlsplit(url).query)["code"][0]

    loaded = await provider.load_authorization_code(client, code)
    assert loaded.pf_key == "api-user-key"
    assert loaded.key_uuid == "u1"
    assert loaded.client_id == client.client_id
    assert loaded.code_challenge == "challenge"
    assert str(loaded.redirect_uri) == REDIRECT
    assert loaded.redirect_uri_provided_explicitly is True
    assert loaded.resource == "https://mcp.example.net/mcp"
    assert loaded.scopes == []
    assert time.time() < loaded.expires_at <= time.time() + 300

    token = await provider.exchange_authorization_code(client, loaded)
    assert token.access_token.startswith("pfmcp_at_")
    assert "api-user-key" not in token.access_token
    assert token.token_type == "Bearer"
    assert TTL - 61 <= token.expires_in <= TTL - 60
    assert token.refresh_token is None

    access = await provider.load_access_token(token.access_token)
    assert isinstance(access, PFAccessToken)
    assert access.token == "api-user-key"
    assert access.key_uuid == "u1"
    assert access.client_id == client.client_id
    assert access.resource == "https://mcp.example.net/mcp"
    assert access.scopes == []
    assert access.expires_at == loaded.key_expires_at


async def test_code_for_other_client_is_none(provider):
    _, code = await issued_code(provider)
    other = await provider.create_client(metadata())
    assert await provider.load_authorization_code(other, code) is None


async def test_garbage_code_is_none(provider):
    client = await provider.create_client(metadata())
    assert await provider.load_authorization_code(client, "pfmcp_code_garbage") is None


async def test_expired_request_and_code(provider, clock):
    _, req = await pending(provider)
    clock["now"] += 601
    with pytest.raises(InvalidRequest):
        await provider.complete_request(req, api_key="api-user-key", key_uuid="u1")
    with pytest.raises(InvalidRequest):
        await provider.describe_request(req)
    with pytest.raises(InvalidRequest):
        await provider.deny_request(req)

    client, code = await issued_code(provider)
    clock["now"] += 301
    assert await provider.load_authorization_code(client, code) is None


async def test_exchange_refuses_expired_key(provider, clock):
    client, code = await issued_code(provider)
    loaded = await provider.load_authorization_code(client, code)
    clock["now"] = loaded.key_expires_at
    with pytest.raises(TokenError) as e:
        await provider.exchange_authorization_code(client, loaded)
    assert e.value.error == "invalid_grant"


async def test_access_token_expires_with_key(provider, clock):
    client, code = await issued_code(provider)
    token = await provider.exchange_authorization_code(client, await provider.load_authorization_code(client, code))
    clock["now"] += TTL
    assert await provider.load_access_token(token.access_token) is None


async def test_deny_request(provider):
    _, req = await pending(provider)
    url = await provider.deny_request(req)
    assert url.startswith(REDIRECT + "?")
    assert "error=access_denied" in url and "state=xyz" in url
    assert "iss=https%3A%2F%2Fmcp.example.net" in url


async def test_refresh_grant_unsupported(provider):
    client = await provider.create_client(metadata())
    assert await provider.load_refresh_token(client, "anything") is None
    with pytest.raises(TokenError) as e:
        await provider.exchange_refresh_token(client, None, [])
    assert e.value.error == "unsupported_grant_type"


async def test_raw_key_passthrough(provider):
    access = await provider.load_access_token("api-pasted")
    assert access.token == "api-pasted"
    assert access.client_id == "api-key"
    assert access.resource == "https://mcp.example.net/mcp"
    assert access.expires_at is None
    assert access.key_uuid is None


async def test_bad_sealed_token_is_none(provider):
    assert await provider.load_access_token("pfmcp_at_garbage") is None


@pytest.mark.parametrize("token", ["pfmcp_aT_garbage", "pfmcp_future_x", "pfmcp_"])
async def test_unknown_pfmcp_tokens_are_not_raw_keys(provider, token):
    assert await provider.load_access_token(token) is None


async def test_key_never_in_repr(provider):
    client, code = await issued_code(provider)
    loaded = await provider.load_authorization_code(client, code)
    token = await provider.exchange_authorization_code(client, loaded)
    access = await provider.load_access_token(token.access_token)
    raw = await provider.load_access_token("api-pasted")
    for model, key in ((loaded, "api-user-key"), (access, "api-user-key"), (raw, "api-pasted")):
        assert key not in repr(model) and key not in str(model)
    assert isinstance(loaded, PFAuthorizationCode) and loaded.pf_key == "api-user-key"
    assert access.token == "api-user-key" and "key_uuid='u1'" in repr(access)


async def test_other_artifacts_are_not_raw_keys(provider):
    client, code = await issued_code(provider)
    _, req = await pending(provider)
    for artifact in (code, req, client.client_id):
        assert await provider.load_access_token(artifact) is None


@respx.mock
async def test_revoke_deletes_key(provider):
    route = respx.delete(f"{BASE}/v2/api-keys/u1").mock(return_value=httpx.Response(200))
    client, code = await issued_code(provider)
    token = await provider.exchange_authorization_code(client, await provider.load_authorization_code(client, code))
    await provider.revoke_token(await provider.load_access_token(token.access_token))
    assert route.call_count == 1
    sent = route.calls.last.request.headers
    assert sent["Authorization"] == "Bearer api-user-key"
    assert "On-Behalf" not in sent

    route.mock(return_value=httpx.Response(500, text="boom"))
    await provider.revoke_token(await provider.load_access_token(token.access_token))
    assert route.call_count == 2


@respx.mock
async def test_revoke_swallows_transport_errors_without_logging_secrets(provider, caplog):
    caplog.set_level(logging.DEBUG)
    route = respx.delete(f"{BASE}/v2/api-keys/uuid-7f3c9e").mock(side_effect=httpx.ConnectError("down"))
    await provider.revoke_token(PFAccessToken(token="api-user-key", client_id="c", scopes=[], key_uuid="uuid-7f3c9e"))
    assert route.call_count == 1
    warnings = [r for r in caplog.records if r.name == provider_mod.__name__ and r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "api-user-key" not in caplog.text and "uuid-7f3c9e" not in caplog.text


@respx.mock
async def test_revoke_raw_key_is_noop(provider):
    route = respx.route().mock(return_value=httpx.Response(200))
    await provider.revoke_token(await provider.load_access_token("api-pasted"))
    assert not route.called


@respx.mock
async def test_delete_api_key_quotes_uuid_and_raises(pf):
    route = respx.delete(f"{BASE}/v2/api-keys/a%2Fb").mock(return_value=httpx.Response(404, text="nope"))
    with pytest.raises(PFError) as e:
        await pf.delete_api_key("api-user-key", "a/b")
    assert route.called
    assert "api-user-key" not in str(e.value)
