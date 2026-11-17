"""Single source of truth for the identity advertised in server.json, the MCP Server Card,
the A2A Agent Card and the AI Catalog. tests/test_discovery.py keeps server.json in sync."""

from __future__ import annotations

import os

from . import __version__

# MCP Registry name. The io.github.PacketFabric/ namespace is proven by publishing from the
# PacketFabric GitHub org (GitHub OIDC). To use com.packetfabric/... instead, add a DNS TXT
# record and switch the publish workflow to `mcp-publisher login dns`.
REGISTRY_NAME = "io.github.PacketFabric/packetfabric-mcp"
PYPI_PACKAGE = "packetfabric-mcp"
VERSION = __version__

TITLE = "PacketFabric"
DESCRIPTION = "Query and manage PacketFabric NaaS: ports, virtual circuits, cloud routers, pricing, metrics."
LONG_DESCRIPTION = (
    "Tools for the PacketFabric Network-as-a-Service API: inventory of ports, virtual circuits, "
    "Cloud Routers and cloud connections; location and pricing lookups; traffic metrics; "
    "maintenance windows; and generic access to every documented API endpoint. "
    "Read-only unless the operator enables writes."
)
ORGANIZATION = "PacketFabric"
ORGANIZATION_URL = "https://packetfabric.com"
REPOSITORY_URL = "https://github.com/PacketFabric/public-mcp"
DOCS_URL = "https://docs.packetfabric.com/api/v2/"
ICON_URL = os.environ.get("PF_ICON_URL") or None

# Paths served by the HTTP app (relative to the public base URL).
MCP_PATH = "/mcp"
SERVER_CARD_PATH = MCP_PATH + "/server-card"  # SEP-2127: <streamable-http-url>/server-card
A2A_PATH = "/a2a"
AGENT_CARD_PATH = "/.well-known/agent-card.json"
LEGACY_AGENT_CARD_PATH = "/.well-known/agent.json"  # pre-0.3 A2A clients still look here
LLMS_TXT_PATH = "/llms.txt"
AI_CATALOG_PATH = "/.well-known/ai-catalog.json"

AUTH_HELP = "Send your PacketFabric API key as 'Authorization: Bearer <key>' (portal: Settings > API Keys)."
A2A_SIGN_IN_TOKEN_HELP = (
    "Signed-in tokens don't work over A2A; send a PacketFabric API key as 'Authorization: Bearer <key>' "
    "(portal: Settings > API Keys)."
)


def catalog_publisher(base_url: str) -> str:
    """Domain used in AI Catalog URNs (urn:air:{publisher}:{kind}:{name})."""
    from urllib.parse import urlparse

    host = urlparse(base_url).hostname or "localhost"
    return host.removeprefix("mcp.").removeprefix("www.")
