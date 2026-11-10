import contextlib
import json
import re
import tomllib
from pathlib import Path

import httpx
import jsonschema
import pytest
import respx

from packetfabric_mcp import __version__, discovery, metadata

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = Path(__file__).parent / "schemas"
BASE = "https://mcp.example.net"
PF = "https://api.packetfabric.com"


# ---------------------------------------------------------------- static metadata


def test_versions_in_sync():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    server = json.loads((ROOT / "server.json").read_text())
    assert pyproject["project"]["version"] == __version__ == metadata.VERSION
    assert server["version"] == __version__
    assert all(p["version"] == __version__ for p in server["packages"])


def test_server_json_matches_metadata_and_schema():
    server = json.loads((ROOT / "server.json").read_text())
    assert server["name"] == metadata.REGISTRY_NAME
    assert server["description"] == metadata.DESCRIPTION
    assert server["title"] == metadata.TITLE
    assert server["packages"][0]["identifier"] == metadata.PYPI_PACKAGE
    jsonschema.validate(server, json.loads((SCHEMAS / "server.schema.json").read_text()))


def test_readme_has_registry_ownership_marker():
    # The MCP Registry verifies PyPI ownership by finding this in the package README.
    readme = (ROOT / "README.md").read_text()
    assert re.search(r"mcp-name: " + re.escape(metadata.REGISTRY_NAME) + r"(\s|-->)", readme)


def test_server_card_valid():
    card = discovery.build_server_card(BASE)
    jsonschema.validate(card, json.loads((SCHEMAS / "server-card.schema.json").read_text()))
    assert card["remotes"][0]["url"] == BASE + "/mcp"
    assert card["name"] == metadata.REGISTRY_NAME


def test_ai_catalog_shape():
    cat = discovery.build_ai_catalog(BASE)
    assert cat["specVersion"] == "1.0" and cat["host"]["displayName"]
    types = {e["type"]: e for e in cat["entries"]}
    assert types["application/mcp-server-card+json"]["url"] == BASE + "/mcp/server-card"
    assert types["application/a2a-agent-card+json"]["url"] == BASE + "/.well-known/agent-card.json"
    for e in cat["entries"]:
        assert re.fullmatch(r"urn:air:example\.net:(mcp|a2a):packetfabric", e["identifier"])


# ---------------------------------------------------------------- live HTTP app


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("PF_TOKEN", "operator-key")  # must NOT be used by the hosted app
    from packetfabric_mcp import server
    from packetfabric_mcp.http_app import build_app

    server._client = None
    a = build_app(public_url=BASE)
    yield a
    server._client = None


@contextlib.asynccontextmanager
async def serve(app):
    # Entered and exited inside the test's own task (anyio cancel scopes require it).
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765") as c:
            yield c


async def test_discovery_endpoints(app):
    async with serve(app) as http:
        r = await http.get("/.well-known/ai-catalog.json")
        assert r.status_code == 200 and r.headers["content-type"].startswith("application/ai-catalog+json")
        assert r.headers["access-control-allow-origin"] == "*"
        urls = [e["url"] for e in r.json()["entries"]]

        r = await http.get("/mcp/server-card", headers={"Accept": "application/mcp-server-card+json"})
        assert r.status_code == 200 and r.json()["remotes"][0]["url"] == f"{BASE}/mcp"
        assert f"{BASE}/mcp/server-card" in urls
        etag = r.headers["etag"]
        assert (await http.get("/mcp/server-card", headers={"If-None-Match": etag})).status_code == 304

        r = await http.get("/.well-known/agent-card.json")
        assert r.status_code == 200
        card = r.json()
        assert card["supportedInterfaces"][0] == {"url": f"{BASE}/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        assert {s["id"] for s in card["skills"]} >= {"list_ports", "get_pricing", "call_endpoint"}
        assert "httpAuthSecurityScheme" in card["securitySchemes"]["packetfabricApiKey"]
        assert (await http.get("/healthz")).json()["version"] == __version__


def _a2a(skill_payload, msg_id="m1"):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {"message": {"messageId": msg_id, "role": "ROLE_USER", "parts": [{"data": skill_payload}]}},
    }


A2A_HEADERS = {"A2A-Version": "1.0", "Content-Type": "application/json"}


@respx.mock
async def test_a2a_skill_uses_callers_key(app, respx_mock):
    async with serve(app) as http:
        route = respx_mock.get(f"{PF}/v2/locations").mock(return_value=httpx.Response(200, json=[{"pop": "NYC5"}]))
        r = await http.post(
            "/a2a",
            json=_a2a({"skill": "find_locations", "arguments": {"market": "NYC"}}),
            headers={**A2A_HEADERS, "Authorization": "Bearer caller-key"},
        )
        body = r.json()
        task = body["result"]["task"]
        assert task["status"]["state"] == "TASK_STATE_COMPLETED", body
        assert task["artifacts"][0]["parts"][0]["data"]["data"][0]["pop"] == "NYC5"
        assert route.calls.last.request.headers["Authorization"] == "Bearer caller-key"


async def test_a2a_without_key_gets_message_and_never_uses_operator_key(app):
    async with serve(app) as http:
        r = await http.post("/a2a", json=_a2a({"skill": "get_account"}), headers=A2A_HEADERS)
        result = r.json()["result"]
        assert "task" not in result  # no task is created for keyless callers
        assert "API key" in result["message"]["parts"][0]["text"]


async def test_a2a_unknown_skill_gets_help(app):
    async with serve(app) as http:
        r = await http.post("/a2a", json=_a2a({"skill": "nope"}), headers=A2A_HEADERS)
        msg = r.json()["result"]["message"]
        assert "Unknown skill" in msg["parts"][0]["text"] and "list_ports" in msg["parts"][0]["text"]


async def test_a2a_call_endpoint_rejects_writes(app):
    async with serve(app) as http:
        r = await http.post(
            "/a2a",
            json=_a2a({"skill": "call_endpoint", "arguments": {"operation_id": "port_post", "body": {}}}),
            headers={**A2A_HEADERS, "Authorization": "Bearer caller-key"},
        )
        assert r.json()["result"]["task"]["status"]["state"] == "TASK_STATE_REJECTED"


@respx.mock
async def test_mcp_over_http_uses_callers_key(app, respx_mock):
    async with serve(app) as http:
        route = respx_mock.get(f"{PF}/v2/customers/current").mock(return_value=httpx.Response(200, json={"name": "X"}))
        hdrs = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        init = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        }  # fmt: skip
        assert (await http.post("/mcp", json=init, headers=hdrs)).status_code == 200
        call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "pf_get_account", "arguments": {}}}
        proto = {"MCP-Protocol-Version": "2025-11-25"}

        r = await http.post("/mcp", json=call, headers={**hdrs, **proto})
        assert r.json()["result"]["isError"] is True and "API key" in r.text  # operator key not used
        assert not route.called

        r = await http.post("/mcp", json=call, headers={**hdrs, **proto, "Authorization": "Bearer caller-key"})
        assert r.json()["result"]["isError"] is False, r.text
        assert route.calls.last.request.headers["Authorization"] == "Bearer caller-key"


async def test_legacy_agent_card_path_and_cors(app):
    async with serve(app) as http:
        new = await http.get("/.well-known/agent-card.json")
        old = await http.get("/.well-known/agent.json")
        assert new.status_code == old.status_code == 200
        assert old.json() == new.json()
        for path in ("/.well-known/agent-card.json", "/.well-known/agent.json", "/.well-known/ai-catalog.json",
                     "/mcp/server-card", "/llms.txt"):  # fmt: skip
            r = await http.get(path)
            assert r.headers["access-control-allow-origin"] == "*", path
            pre = await http.options(path, headers={"Origin": "https://x.example", "Access-Control-Request-Method": "GET"})
            assert pre.status_code == 204 and pre.headers["access-control-allow-origin"] == "*", path


async def test_llms_txt_and_home_page(app):
    async with serve(app) as http:
        r = await http.get("/llms.txt")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
        assert r.text.startswith("# PacketFabric")
        for path in ("/mcp", "/mcp/server-card", "/.well-known/agent-card.json", "/.well-known/ai-catalog.json"):
            assert f"({BASE}{path})" in r.text
        r = await http.get("/")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
        assert f'href="{BASE}/.well-known/agent-card.json"' in r.text and __version__ in r.text
        # The MCP endpoint itself is unaffected by the new root route.
        assert (await http.get("/healthz")).json()["version"] == __version__
