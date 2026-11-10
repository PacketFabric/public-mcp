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


def build_llms_txt(base_url: str) -> str:
    """llms.txt (https://llmstxt.org) for the MCP host: what this service is and where everything lives."""
    base = base_url.rstrip("/")
    return f"""# {metadata.TITLE} MCP and A2A

> {metadata.LONG_DESCRIPTION} Authenticate every request with `Authorization: Bearer <PacketFabric API key>`.

## For AI agents

- [MCP server]({base}{metadata.MCP_PATH}): Model Context Protocol endpoint (streamable HTTP)
- [MCP server card]({base}{metadata.SERVER_CARD_PATH}): connection details for the MCP server
- [A2A agent card]({base}{metadata.AGENT_CARD_PATH}): Agent2Agent v1.0 agent; JSON-RPC endpoint at {base}{metadata.A2A_PATH}
- [AI catalog]({base}{metadata.AI_CATALOG_PATH}): index of the services above
- [MCP Registry listing](https://registry.modelcontextprotocol.io/v0/servers?search={metadata.REGISTRY_NAME}): `{metadata.REGISTRY_NAME}`
- [Local install](https://pypi.org/project/{metadata.PYPI_PACKAGE}/): `uvx {metadata.PYPI_PACKAGE}`

## API

- [API documentation]({metadata.DOCS_URL}): PacketFabric REST API reference
- [Source code]({metadata.REPOSITORY_URL}): this server, MPL-2.0

## Optional

- [PacketFabric]({metadata.ORGANIZATION_URL}): products, locations and pricing
"""


def build_home_page(base_url: str) -> str:
    """Small human-readable landing page for the bare host (people arrive here from registry links)."""
    from html import escape

    base = escape(base_url.rstrip("/"))
    rows = [
        ("MCP endpoint", f"{base}{metadata.MCP_PATH}", "Streamable HTTP. Send <code>Authorization: Bearer &lt;PacketFabric API key&gt;</code>."),
        ("MCP server card", f"{base}{metadata.SERVER_CARD_PATH}", "Connection details (SEP-2127)."),
        ("A2A agent card", f"{base}{metadata.AGENT_CARD_PATH}", f"Agent2Agent v1.0; JSON-RPC at <code>{base}{metadata.A2A_PATH}</code>."),
        ("AI catalog", f"{base}{metadata.AI_CATALOG_PATH}", "Index of the services above."),
        ("llms.txt", f"{base}{metadata.LLMS_TXT_PATH}", "Summary for language models."),
    ]
    items = "\n".join(
        f'<tr><th>{name}</th><td><a href="{url}">{url}</a><br><span>{note}</span></td></tr>' for name, url, note in rows
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(metadata.TITLE)} MCP server</title>
<style>
:root{{--bg:#fff;--fg:#1a1a1a;--muted:#5f6368;--line:#e3e3e3;--link:#0b57d0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#141414;--fg:#ececec;--muted:#a0a0a0;--line:#2e2e2e;--link:#8ab4f8}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:760px;margin:0 auto;padding:40px 16px}}
h1{{font-size:1.6rem;margin:0 0 8px}} p{{color:var(--muted);margin:0 0 24px}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;vertical-align:top;padding:12px 8px;border-top:1px solid var(--line)}}
th{{width:30%;font-weight:600}} td{{word-break:break-all}} td span{{color:var(--muted);font-size:.9rem;word-break:normal}}
a{{color:var(--link)}} code{{font-size:.9em}} footer{{margin-top:32px;color:var(--muted);font-size:.9rem}}
</style></head>
<body><main>
<h1>{escape(metadata.TITLE)} MCP server</h1>
<p>{escape(metadata.LONG_DESCRIPTION)}</p>
<table>{items}</table>
<footer>Version {escape(metadata.VERSION)} &middot; <a href="{metadata.DOCS_URL}">API docs</a> &middot;
<a href="{metadata.REPOSITORY_URL}">Source (MPL-2.0)</a> &middot; <a href="{metadata.ORGANIZATION_URL}">packetfabric.com</a></footer>
</main></body></html>
"""
