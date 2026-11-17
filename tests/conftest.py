import contextlib
import time
import types

import httpx
import pytest
from cryptography.fernet import Fernet

from packetfabric_mcp.client import PacketFabricClient
from packetfabric_mcp.oauth import provider as provider_mod
from packetfabric_mcp.oauth.config import DEFAULT_ALLOWED_REDIRECTS, OAuthConfig
from packetfabric_mcp.oauth.provider import PacketFabricOAuthProvider
from packetfabric_mcp.oauth.seal import Sealer

BASE = "https://api.packetfabric.com"
TTL = 2_592_000
PORTAL_ORIGINS = ("https://portal.example.net", "https://*.portal.example.net")


@pytest.fixture
def cfg():
    return OAuthConfig(
        secrets=(Fernet.generate_key().decode(),),
        public_url="https://mcp.example.net",
        portal_url="https://portal.example.net",
        portal_origins=PORTAL_ORIGINS,
        allowed_redirects=DEFAULT_ALLOWED_REDIRECTS,
        key_ttl_seconds=TTL,
    )


@pytest.fixture
async def pf(monkeypatch):
    # Operator credentials are set on purpose: provider calls must never use them.
    monkeypatch.setenv("PF_TOKEN", "operator-key")
    monkeypatch.setenv("PF_ON_BEHALF", "operator-account")
    monkeypatch.delenv("PF_API_URL", raising=False)
    client = PacketFabricClient(BASE)
    yield client
    await client.aclose()


@pytest.fixture
def provider(cfg, pf):
    return PacketFabricOAuthProvider(cfg, Sealer(cfg.secrets), pf)


@pytest.fixture
def clock(monkeypatch):
    state = {"now": time.time()}
    monkeypatch.setattr(provider_mod, "time", types.SimpleNamespace(time=lambda: state["now"]))
    return state


@contextlib.asynccontextmanager
async def serve(app):
    # Entered and exited inside the test's own task (anyio cancel scopes require it).
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765") as c:
            yield c
