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

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from . import discovery, metadata
from .server import client, mcp

log = logging.getLogger(__name__)

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, If-None-Match",
    "Access-Control-Expose-Headers": "ETag",
}


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


def build_app(
    public_url: str | None = None, enable_a2a: bool | None = None, bind_host: str = "127.0.0.1"
) -> Starlette:
    public_url = public_url or os.environ.get("PF_PUBLIC_URL") or None
    client().require_caller_token = not _env_true("PF_HTTP_USE_SERVER_CREDENTIALS")

    a2a_routes: list[Route] = []
    agent_card = None
    want_a2a = enable_a2a if enable_a2a is not None else not _env_true("PF_DISABLE_A2A")
    if want_a2a:
        try:
            from a2a.server.request_handlers import DefaultRequestHandlerV2
            from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
            from a2a.server.tasks import InMemoryTaskStore

            from .a2a_agent import PacketFabricAgentExecutor, build_agent_card

            # The agent card needs an absolute URL; without PF_PUBLIC_URL fall back to the bind address.
            agent_card = build_agent_card(public_url or f"http://{bind_host}:{os.environ.get('PF_PORT', '8765')}")
            handler = DefaultRequestHandlerV2(
                agent_executor=PacketFabricAgentExecutor(), task_store=InMemoryTaskStore(), agent_card=agent_card
            )
            a2a_routes = [
                *create_agent_card_routes(agent_card, cache_control="public, max-age=3600"),
                *create_jsonrpc_routes(handler, rpc_url=metadata.A2A_PATH),
            ]
        except ImportError:
            log.info("a2a-sdk not installed; serving MCP only (pip install 'packetfabric-mcp[a2a]').")

    async def server_card(request: Request) -> Response:
        return _doc_response(
            request, discovery.build_server_card(_base_url(request, public_url)), discovery.SERVER_CARD_MEDIA_TYPE
        )

    async def ai_catalog(request: Request) -> Response:
        doc = discovery.build_ai_catalog(_base_url(request, public_url), include_a2a=agent_card is not None)
        return _doc_response(request, doc, discovery.AI_CATALOG_MEDIA_TYPE)

    async def preflight(request: Request) -> Response:
        return Response(status_code=204, headers=CORS_HEADERS)

    async def healthz(request: Request) -> Response:
        return JSONResponse({"ok": True, "version": metadata.VERSION})

    app = mcp.streamable_http_app(
        streamable_http_path=metadata.MCP_PATH,
        stateless_http=True,  # no sticky sessions needed; scales horizontally
        json_response=True,
        host=bind_host,  # localhost binds get the SDK's DNS-rebinding protection
    )
    # Discovery routes go first so /mcp/server-card isn't swallowed by the /mcp mount.
    app.router.routes[0:0] = [
        Route(metadata.SERVER_CARD_PATH, server_card, methods=["GET"]),
        Route(metadata.SERVER_CARD_PATH, preflight, methods=["OPTIONS"]),
        Route(metadata.AI_CATALOG_PATH, ai_catalog, methods=["GET"]),
        Route(metadata.AI_CATALOG_PATH, preflight, methods=["OPTIONS"]),
        Route("/healthz", healthz, methods=["GET"]),
        *a2a_routes,
    ]
    return app
