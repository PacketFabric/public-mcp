"""Discovery documents.

- MCP Server Card (SEP-2127), served at <streamable-http-url>/server-card
- AI Catalog, served at /.well-known/ai-catalog.json, listing the Server Card and the A2A Agent Card
- server.json for the MCP Registry is a static file in the repo root, kept in sync by tests.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mcp.types.version import SUPPORTED_PROTOCOL_VERSIONS

from . import metadata

SERVER_CARD_SCHEMA = "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json"
SERVER_CARD_MEDIA_TYPE = "application/mcp-server-card+json"
AGENT_CARD_MEDIA_TYPE = "application/a2a-agent-card+json"
AI_CATALOG_MEDIA_TYPE = "application/ai-catalog+json"

AUTH_HEADER = {
    "name": "Authorization",
    "description": "Bearer <your PacketFabric API key> (portal: Settings > API Keys)",
    "isRequired": True,
    "isSecret": True,
    "value": "Bearer {api_key}",
    "variables": {"api_key": {"description": "PacketFabric API key", "isRequired": True, "isSecret": True}},
}


def _repository() -> dict[str, str]:
    return {"url": metadata.REPOSITORY_URL, "source": "github"}


def build_server_card(base_url: str) -> dict[str, Any]:
    base = base_url.rstrip("/")
    card: dict[str, Any] = {
        "$schema": SERVER_CARD_SCHEMA,
        "name": metadata.REGISTRY_NAME,
        "version": metadata.VERSION,
        "title": metadata.TITLE,
        "description": metadata.DESCRIPTION,
        "websiteUrl": metadata.REPOSITORY_URL,
        "repository": _repository(),
        "remotes": [
            {
                "type": "streamable-http",
                "url": base + metadata.MCP_PATH,
                "headers": [AUTH_HEADER],
                "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
            }
        ],
    }
    if metadata.ICON_URL:
        card["icons"] = [{"src": metadata.ICON_URL}]
    return card


def build_ai_catalog(base_url: str, include_a2a: bool = True) -> dict[str, Any]:
    base = base_url.rstrip("/")
    publisher = metadata.catalog_publisher(base)
    entries = [
        {
            "identifier": f"urn:air:{publisher}:mcp:packetfabric",
            "type": SERVER_CARD_MEDIA_TYPE,
            "url": base + metadata.SERVER_CARD_PATH,
            "displayName": f"{metadata.TITLE} MCP server",
            "description": metadata.DESCRIPTION,
            "version": metadata.VERSION,
            "tags": ["networking", "naas", "packetfabric", "mcp"],
        }
    ]
    if include_a2a:
        entries.append(
            {
                "identifier": f"urn:air:{publisher}:a2a:packetfabric",
                "type": AGENT_CARD_MEDIA_TYPE,
                "url": base + metadata.AGENT_CARD_PATH,
                "displayName": f"{metadata.TITLE} Network Agent (A2A)",
                "description": metadata.DESCRIPTION,
                "version": metadata.VERSION,
                "tags": ["networking", "naas", "packetfabric", "a2a"],
            }
        )
    return {
        "specVersion": "1.0",
        "host": {
            "displayName": metadata.ORGANIZATION,
            "identifier": publisher,
            "documentationUrl": metadata.REPOSITORY_URL,
        },
        "entries": entries,
    }


def etag_for(doc: Any) -> str:
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return '"' + hashlib.sha256(raw).hexdigest()[:32] + '"'
