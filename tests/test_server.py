import json

import httpx
import pytest
import respx

BASE = "https://api.packetfabric.com"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("PF_TOKEN", "test-key")
    for var in ("PF_LOGIN", "PF_PASSWORD", "PF_ON_BEHALF", "PF_API_URL"):
        monkeypatch.delenv(var, raising=False)
    from packetfabric_mcp import server

    server._client = None  # fresh client per test (picks up env)
    monkeypatch.setattr(server, "ALLOW_WRITES", False)
    yield server
    server._client = None


class Result:
    """What the MCP client sees: text content plus an is_error flag."""

    def __init__(self, text, is_error=False):
        self.text, self.is_error = text, is_error


def text(result):
    return result.text


async def call(server, name, args=None):
    from mcp.server.mcpserver.exceptions import ToolError

    try:
        r = await server.mcp.call_tool(name, args or {})
    except ToolError as e:  # over the wire this becomes CallToolResult(isError=True)
        return Result(str(e), True)
    return Result(r.content[0].text, bool(r.is_error))


async def test_tool_count_is_small(env):
    tools = await env.mcp.list_tools()
    names = {t.name for t in tools}
    assert len(tools) <= 20
    assert {"pf_search_endpoints", "pf_describe_endpoint", "pf_call_endpoint", "pf_list_ports"} <= names


def test_spec_index():
    from packetfabric_mcp.spec import Spec

    s = Spec.load()
    assert len(s.operations) > 300
    assert s.get("post_api_key") is None  # blocked tag
    assert s.get("get_port_list").is_read_only
    assert not s.get("delete_port").is_read_only
    assert s.search("cloud router bgp")[0].operation_id.startswith("cloud_router")


async def test_search_and_describe(env):
    r = json.loads(text(await call(env, "pf_search_endpoints", {"query": "port metrics rate"})))
    ids = [x["operation_id"] for x in r["results"]]
    assert "ifd_rate" in ids
    d = json.loads(text(await call(env, "pf_describe_endpoint", {"operation_id": "ifd_rate"})))
    assert {p["name"] for p in d["parameters"]} >= {"type", "port_circuit_id", "since"}


async def test_describe_unknown_suggests(env):
    r = await call(env, "pf_describe_endpoint", {"operation_id": "get_ports_list"})
    assert r.is_error and "Did you mean" in text(r)


@respx.mock
async def test_curated_read_sends_auth_and_filters(env):
    route = respx.get(f"{BASE}/v2/ports").mock(
        return_value=httpx.Response(200, json=[{"port_circuit_id": f"PF-AP-LAX1-{i}", "pop": "LAX1"} for i in range(5)])
    )
    r = await call(env, "pf_list_ports", {"pop": "LAX1", "is_lag": False, "max_items": 2, "fields": ["port_circuit_id"]})
    req = route.calls.last.request
    assert req.headers["Authorization"] == "Bearer test-key"
    assert req.url.params["pop"] == "LAX1" and req.url.params["is_lag"] == "false"
    body = json.loads(text(r))
    assert body["_meta"] == {"total_items": 5, "truncated_to": 2, "hint": body["_meta"]["hint"]}
    assert body["data"] == [{"port_circuit_id": "PF-AP-LAX1-0"}, {"port_circuit_id": "PF-AP-LAX1-1"}]


@respx.mock
async def test_list_query_params_repeat(env):
    route = respx.get(f"{BASE}/v2/services").mock(return_value=httpx.Response(200, json=[]))
    await call(env, "pf_list_services", {"service_type": ["backbone", "ix"]})
    assert route.calls.last.request.url.params.get_list("service_type") == ["backbone", "ix"]


@respx.mock
async def test_generic_call_with_path_params(env):
    route = respx.get(f"{BASE}/v2/metrics/ifd/rate/bps/PF-AP-LAX1-1").mock(return_value=httpx.Response(200, json=[]))
    r = await call(
        env, "pf_call_endpoint",
        {"operation_id": "ifd_rate", "params": {"type": "bps", "port_circuit_id": "PF-AP-LAX1-1", "since": "1 day ago"}},
    )  # fmt: skip
    assert not r.is_error
    assert route.calls.last.request.url.params["since"] == "1 day ago"


async def test_missing_path_param(env):
    r = await call(env, "pf_call_endpoint", {"operation_id": "ifd_rate", "params": {"type": "bps"}})
    assert r.is_error and "port_circuit_id" in text(r)


@respx.mock
async def test_api_error_surfaces(env):
    respx.get(f"{BASE}/v2/customers/current").mock(return_value=httpx.Response(403, json={"message": "nope"}))
    r = await call(env, "pf_get_account")
    assert r.is_error and "403" in text(r) and "nope" in text(r)


async def test_writes_blocked_by_default(env):
    r = await call(env, "pf_call_endpoint", {"operation_id": "port_post", "body": {"speed": "10Gbps"}})
    assert r.is_error and "disabled" in text(r)


@respx.mock
async def test_write_needs_confirm(env, monkeypatch):
    monkeypatch.setattr(env, "ALLOW_WRITES", True)
    route = respx.post(f"{BASE}/v2/ports").mock(return_value=httpx.Response(201, json={"port_circuit_id": "PF-AP-X"}))
    r = json.loads(text(await call(env, "pf_call_endpoint", {"operation_id": "port_post", "body": {"speed": "10Gbps"}})))
    assert r["dry_run"] is True and not route.called
    r = await call(env, "pf_call_endpoint", {"operation_id": "port_post", "body": {"speed": "10Gbps"}, "confirm": True})
    assert route.called and json.loads(route.calls.last.request.content) == {"speed": "10Gbps"}
    assert "PF-AP-X" in text(r)


@respx.mock
async def test_login_flow_and_reauth(env, monkeypatch):
    monkeypatch.delenv("PF_TOKEN")
    monkeypatch.setenv("PF_LOGIN", "chad")
    monkeypatch.setenv("PF_PASSWORD", "pw")
    monkeypatch.setenv("PF_ON_BEHALF", "cust-uuid")
    env._client = None
    login = respx.post(f"{BASE}/v2/auth/login").mock(
        side_effect=[httpx.Response(200, json={"token": "t1"}), httpx.Response(200, json={"token": "t2"})]
    )
    acct = respx.get(f"{BASE}/v2/customers/current").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"name": "Entropy"})]
    )
    r = await call(env, "pf_get_account")
    assert "Entropy" in text(r)
    assert login.call_count == 2
    assert acct.calls.last.request.headers["Authorization"] == "Bearer t2"
    assert acct.calls.last.request.headers["On-Behalf"] == "cust-uuid"


async def test_no_credentials(env, monkeypatch):
    monkeypatch.delenv("PF_TOKEN")
    env._client = None
    r = await call(env, "pf_get_account")
    assert r.is_error and "PF_TOKEN" in text(r)
