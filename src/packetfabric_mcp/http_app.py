"""HTTP deployment: MCP (streamable HTTP) + discovery documents + optional A2A, in one ASGI app.

    GET  /.well-known/ai-catalog.json   AI Catalog (lists the two cards below)
    POST /mcp                            MCP streamable HTTP endpoint
    GET  /mcp/server-card                MCP Server Card (SEP-2127)
    GET  /.well-known/agent-card.json    A2A Agent Card          (if a2a-sdk is installed)
    POST /a2a                            A2A JSON-RPC endpoint   (if a2a-sdk is installed)
    GET  /healthz                        liveness

Every caller authenticates with their *own* PacketFabric API key (Authorization: Bearer ...).
The operator's PF_TOKEN / PF_LOGIN are ignored unless PF_HTTP_USE_SERVER_CREDENTIALS=true,
which is only appropriate for a private, single-user deployment.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from . import discovery, metadata
from .oauth.config import OAuthConfig
from .oauth.provider import PacketFabricOAuthProvider
from .oauth.routes import oauth_routes
from .oauth.seal import Sealer
from .server import client, mcp

log = logging.getLogger(__name__)

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, If-None-Match",
    "Access-Control-Expose-Headers": "ETag",
}


MAX_BODY_BYTES = int(os.environ.get("PF_MAX_BODY_BYTES", str(1024 * 1024)))


class BodySizeLimit:
    """Reject request bodies over `max_bytes` with 413: up front from Content-Length, or while
    reading a streamed body. /mcp is skipped: the MCP SDK enforces its own cap."""

    def __init__(self, app: Any, max_bytes: int, skip_prefix: str = metadata.MCP_PATH) -> None:
        self.app, self.max_bytes, self.skip_prefix = app, max_bytes, skip_prefix

    def _skip(self, path: str) -> bool:
        if path == metadata.SERVER_CARD_PATH:
            return False
        return path == self.skip_prefix or path.startswith(self.skip_prefix + "/")

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or self._skip(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await self._reject(send)
                    return

        # No usable Content-Length (e.g. chunked): read the body ourselves, up to the limit, so
        # an oversized request is refused before any route handler sees it, then replay it.
        if scope.get("method") in ("POST", "PUT", "PATCH"):
            chunks: list[bytes] = []
            seen = 0
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    break
                chunk = message.get("body", b"")
                seen += len(chunk)
                if seen > self.max_bytes:
                    await self._reject(send)
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
            replayed = False

            async def replay() -> Any:
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            await self.app(scope, replay, send)
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(send: Any) -> None:
        body = b'{"error":"request body too large"}'
        await send({
            "type": "http.response.start", "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })  # fmt: skip
        await send({"type": "http.response.body", "body": body})


PUBLIC_DOC_PATHS = frozenset(
    {
        metadata.SERVER_CARD_PATH,
        metadata.AI_CATALOG_PATH,
        metadata.AGENT_CARD_PATH,
        metadata.LEGACY_AGENT_CARD_PATH,
        metadata.LLMS_TXT_PATH,
    }
)


class PublicDocCORS:
    """Browser-readable discovery documents: answer CORS preflights and add the CORS headers to
    every response on the public document paths (the SDK's agent-card route doesn't set them)."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self._headers = [(k.lower().encode(), v.encode()) for k, v in CORS_HEADERS.items()]

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") not in PUBLIC_DOC_PATHS:
            await self.app(scope, receive, send)
            return
        if scope.get("method") == "OPTIONS":
            await send({"type": "http.response.start", "status": 204, "headers": self._headers})
            await send({"type": "http.response.body", "body": b""})
            return

        async def with_cors(message: Any) -> None:
            if message["type"] == "http.response.start":
                names = {k for k, _ in self._headers}
                message["headers"] = [h for h in message.get("headers", []) if h[0].lower() not in names] + self._headers
            await send(message)

        await self.app(scope, receive, with_cors)


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


def _base_url(request: Request, configured: str | None) -> str:
    if configured:
        return configured.rstrip("/")
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}"


def _doc_response(request: Request, doc: Any, media_type: str) -> Response:
    etag = discovery.etag_for(doc)
    headers = {**CORS_HEADERS, "Cache-Control": "public, max-age=3600", "ETag": etag}
    if etag in [t.strip() for t in request.headers.get("if-none-match", "").split(",")]:
        return Response(status_code=304, headers=headers)
    return JSONResponse(doc, media_type=media_type, headers=headers)


def _auth_settings(cfg: OAuthConfig) -> AuthSettings:
    # Plain strings, not AnyHttpUrl: the advertised issuer must equal the `iss` the provider
    # puts on redirects exactly (no trailing slash). Scopes stay unset because our /register
    # replaces the SDK's and doesn't apply its scope handling.
    return AuthSettings(
        issuer_url=cfg.public_url,  # type: ignore[arg-type]
        resource_server_url=cfg.resource_url,  # type: ignore[arg-type]
        validate_token_resource=True,
        client_registration_options=ClientRegistrationOptions(enabled=True),
        revocation_options=RevocationOptions(enabled=True),
    )


def _oauth(cfg: OAuthConfig) -> tuple[dict[str, Any], list[Route]]:
    """SDK auth arguments for streamable_http_app, plus our own routes (which must win)."""
    provider = PacketFabricOAuthProvider(cfg, Sealer(cfg.secrets), client())
    sdk_args = {
        "auth": _auth_settings(cfg),
        "token_verifier": ProviderTokenVerifier(provider),
        "auth_server_provider": provider,
    }
    return sdk_args, oauth_routes(provider, cfg)


def build_app(
    public_url: str | None = None, enable_a2a: bool | None = None, bind_host: str = "127.0.0.1"
) -> Starlette:
    public_url = public_url or os.environ.get("PF_PUBLIC_URL") or None
    client().require_caller_token = not _env_true("PF_HTTP_USE_SERVER_CREDENTIALS")
    oauth_cfg = OAuthConfig.from_env(public_url)
    oauth_enabled = oauth_cfg is not None

    a2a_routes: list[Route] = []
    agent_card = None
    want_a2a = enable_a2a if enable_a2a is not None else not _env_true("PF_DISABLE_A2A")
    if want_a2a:
        try:
            from a2a.server.request_handlers import DefaultRequestHandlerV2
            from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
            from .a2a_agent import PacketFabricAgentExecutor, build_agent_card
            from .a2a_store import ScopedTaskStore

            # The agent card needs an absolute URL; without PF_PUBLIC_URL fall back to the bind address.
            agent_card = build_agent_card(public_url or f"http://{bind_host}:{os.environ.get('PF_PORT', '8765')}")
            handler = DefaultRequestHandlerV2(
                agent_executor=PacketFabricAgentExecutor(), task_store=ScopedTaskStore(), agent_card=agent_card
            )
            a2a_routes = [
                *create_agent_card_routes(agent_card, cache_control="public, max-age=3600"),
                *create_agent_card_routes(
                    agent_card, card_url=metadata.LEGACY_AGENT_CARD_PATH, cache_control="public, max-age=3600"
                ),
                *create_jsonrpc_routes(handler, rpc_url=metadata.A2A_PATH),
            ]
        except ImportError:
            log.info("a2a-sdk not installed; serving MCP only (pip install 'packetfabric-mcp[a2a]').")

    async def server_card(request: Request) -> Response:
        return _doc_response(
            request,
            discovery.build_server_card(_base_url(request, public_url), oauth_enabled=oauth_enabled),
            discovery.SERVER_CARD_MEDIA_TYPE,
        )

    async def ai_catalog(request: Request) -> Response:
        doc = discovery.build_ai_catalog(_base_url(request, public_url), include_a2a=agent_card is not None)
        return _doc_response(request, doc, discovery.AI_CATALOG_MEDIA_TYPE)

    async def llms_txt(request: Request) -> Response:
        body = discovery.build_llms_txt(_base_url(request, public_url), oauth_enabled=oauth_enabled)
        return PlainTextResponse(body, headers={"Cache-Control": "public, max-age=3600"})

    async def home(request: Request) -> Response:
        return HTMLResponse(discovery.build_home_page(_base_url(request, public_url), oauth_enabled=oauth_enabled))

    async def healthz(request: Request) -> Response:
        return JSONResponse({"ok": True, "version": metadata.VERSION})

    http_args: dict[str, Any] = {
        "streamable_http_path": metadata.MCP_PATH,
        "stateless_http": True,  # no sticky sessions needed; scales horizontally
        "json_response": True,
        "host": bind_host,  # localhost binds get the SDK's DNS-rebinding protection
    }
    sign_in_routes: list[Route] = []
    if oauth_cfg is None:
        app = mcp.streamable_http_app(**http_args)
    else:
        sdk_auth_args, sign_in_routes = _oauth(oauth_cfg)
        # MCPServer.streamable_http_app only reads auth from attributes fixed when `mcp` was
        # created at import time, so the OAuth app is built from the low-level server directly.
        app = mcp._lowlevel_server.streamable_http_app(
            **http_args,
            **sdk_auth_args,
            custom_starlette_routes=mcp._custom_starlette_routes,
            debug=mcp.settings.debug,
        )
    # Our routes go first: our /register replaces the SDK's, and /mcp/server-card mustn't be
    # swallowed by the /mcp mount.
    app.router.routes[0:0] = [
        *sign_in_routes,
        Route(metadata.SERVER_CARD_PATH, server_card, methods=["GET"]),
        Route(metadata.AI_CATALOG_PATH, ai_catalog, methods=["GET"]),
        Route(metadata.LLMS_TXT_PATH, llms_txt, methods=["GET"]),
        Route("/", home, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
        *a2a_routes,
    ]
    app.add_middleware(BodySizeLimit, max_bytes=MAX_BODY_BYTES)
    app.add_middleware(PublicDocCORS)
    return app
