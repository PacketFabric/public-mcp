"""Regression tests for the A2A cross-caller task leak (fixed in 0.2.2) and related hardening."""

import contextlib
import json

import httpx
import pytest
import respx

BASE = "https://mcp.example.net"
PF = "https://api.packetfabric.com"
H = {"A2A-Version": "1.0", "Content-Type": "application/json"}
A = {**H, "Authorization": "Bearer key-customer-a"}
B = {**H, "Authorization": "Bearer key-customer-b"}
SECRET = "PF-AP-LAX1-SECRET"


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("PF_TOKEN", "operator-key")
    from packetfabric_mcp import server
    from packetfabric_mcp.http_app import build_app

    server._client = None
    yield build_app(public_url=BASE)
    server._client = None


@contextlib.asynccontextmanager
async def serve(app):
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765") as c:
            yield c


def rpc(method, params, i=1):
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params}


def send(skill, task_id=None, msg_id="m1", **arguments):
    message = {"messageId": msg_id, "role": "ROLE_USER", "parts": [{"data": {"skill": skill, "arguments": arguments}}]}
    if task_id:
        message["taskId"] = task_id
    return rpc("SendMessage", {"message": message})


def _store(app):
    for route in app.router.routes:
        endpoint = getattr(route, "endpoint", None)
        handler = getattr(getattr(endpoint, "__self__", None), "request_handler", None) or getattr(
            endpoint, "request_handler", None
        )
        if handler is not None:
            return handler.task_store
    from packetfabric_mcp.a2a_store import ScopedTaskStore

    found = [o for o in __import__("gc").get_objects() if isinstance(o, ScopedTaskStore)]
    return found[-1]


async def _a_runs_a_task(http):
    with respx.mock:
        respx.get(f"{PF}/v2/ports").mock(return_value=httpx.Response(200, json=[{"port_circuit_id": SECRET}]))
        r = await http.post("/a2a", json=send("list_ports", pop="LAX1"), headers=A)
    task = r.json()["result"]["task"]
    assert task["status"]["state"] == "TASK_STATE_COMPLETED"
    assert SECRET in json.dumps(task)
    return task["id"]


@pytest.mark.parametrize("who", ["anonymous", "other_key", "same_key_other_customer"])
async def test_other_callers_cannot_list_tasks(app, who):
    headers = {"anonymous": H, "other_key": B, "same_key_other_customer": {**A, "On-Behalf": "cust-2"}}[who]
    async with serve(app) as http:
        await _a_runs_a_task(http)
        r = await http.post("/a2a", json=rpc("ListTasks", {"includeArtifacts": True}), headers=headers)
        assert SECRET not in r.text
        assert r.json()["result"].get("tasks", []) == []


async def test_owner_can_list_own_tasks(app):
    async with serve(app) as http:
        task_id = await _a_runs_a_task(http)
        r = await http.post("/a2a", json=rpc("ListTasks", {"includeArtifacts": True}), headers=A)
        assert [t["id"] for t in r.json()["result"]["tasks"]] == [task_id]
        r = await http.post("/a2a", json=rpc("GetTask", {"id": task_id}), headers=A)
        assert SECRET in r.text


@pytest.mark.parametrize("headers", [H, B], ids=["anonymous", "other_key"])
async def test_other_callers_cannot_get_task_by_id(app, headers):
    async with serve(app) as http:
        task_id = await _a_runs_a_task(http)
        r = await http.post("/a2a", json=rpc("GetTask", {"id": task_id}), headers=headers)
        assert SECRET not in r.text
        assert "error" in r.json()


@pytest.mark.parametrize("headers", [H, B], ids=["anonymous", "other_key"])
async def test_other_callers_cannot_send_into_task(app, headers):
    async with serve(app) as http:
        task_id = await _a_runs_a_task(http)
        with respx.mock:
            respx.get(f"{PF}/v2/ports").mock(return_value=httpx.Response(200, json=[]))
            r = await http.post("/a2a", json=send("list_ports", task_id=task_id, msg_id="m2"), headers=headers)
        assert SECRET not in r.text
        # Must look like the task doesn't exist (not "already completed", which confirms it does).
        assert "TASK_NOT_FOUND" in r.text


async def test_keyless_calls_store_nothing(app):
    async with serve(app) as http:
        for i in range(5):
            await http.post("/a2a", json=send("get_account", msg_id=f"x{i}"), headers=H)
            await http.post("/a2a", json=send("nope", msg_id=f"y{i}"), headers=H)
        assert len(_store(app)) == 0


async def test_store_is_bounded():
    from a2a.server.context import ServerCallContext
    from a2a.types import Task

    from packetfabric_mcp.a2a_store import ScopedTaskStore

    def ctx(key):
        return ServerCallContext(state={"headers": {"authorization": f"Bearer {key}"}})

    store = ScopedTaskStore(max_tasks=5, max_tasks_per_owner=3, ttl_seconds=3600)
    for i in range(10):
        await store.save(Task(id=f"a{i}", context_id="c"), ctx("A"))
    assert len(store) == 3  # per-caller cap keeps the newest
    assert await store.get("a9", ctx("A")) is not None and await store.get("a0", ctx("A")) is None
    for i in range(10):
        await store.save(Task(id=f"k{i}", context_id="c"), ctx(f"key{i}"))
    assert len(store) == 5  # global cap

    ttl_store = ScopedTaskStore(ttl_seconds=0.01)
    await ttl_store.save(Task(id="t", context_id="c"), ctx("A"))
    import asyncio

    await asyncio.sleep(0.05)
    assert await ttl_store.get("t", ctx("A")) is None and len(ttl_store) == 0


async def test_a2a_body_size_limit(app):
    async with serve(app) as http:
        big = json.dumps(rpc("SendMessage", {"x": "a" * (2 * 1024 * 1024)})).encode()
        r = await http.post("/a2a", content=big, headers=A)
        assert r.status_code == 413

        async def chunks():  # no Content-Length: streamed body must be counted too
            for _ in range(40):
                yield b"a" * 65536

        r = await http.post("/a2a", content=chunks(), headers=A)
        assert r.status_code == 413

        r = await http.post("/a2a", json=send("nope"), headers=A)  # normal requests unaffected
        assert r.status_code == 200


@respx.mock
async def test_cookies_never_shared_between_callers():
    from packetfabric_mcp.client import PacketFabricClient, CallerCredentials, caller_credentials
    from packetfabric_mcp.spec import Spec

    spec = Spec.load()
    client = PacketFabricClient(spec.base_url)
    route = respx.get(f"{PF}/v2/customers/current").mock(
        return_value=httpx.Response(200, json={}, headers={"Set-Cookie": "session=caller-a; Path=/"})
    )
    for key in ("a", "b"):
        tok = caller_credentials.set(CallerCredentials(token=key))
        try:
            await client.request(spec.get("customer_get"))
        finally:
            caller_credentials.reset(tok)
    assert "cookie" not in route.calls.last.request.headers
    await client.aclose()
