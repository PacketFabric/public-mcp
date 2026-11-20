"""PacketFabric MCP server.

Design: ~15 tools instead of 346. A handful of curated read-only tools cover the
everyday questions; three discovery/execution tools (search, describe, call) reach
every other endpoint in the spec. Anything that changes state is disabled unless
PF_ALLOW_WRITES=true, and even then needs an explicit confirm=true on the call.
"""

from __future__ import annotations

import json
import os
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import metadata
from .client import PacketFabricClient, PFError, caller_credentials, credentials_from_headers
from .spec import Operation, Spec

ALLOW_WRITES = os.environ.get("PF_ALLOW_WRITES", "").lower() in ("1", "true", "yes", "on")
MAX_CHARS = int(os.environ.get("PF_MAX_RESPONSE_CHARS", "60000"))
DEFAULT_MAX_ITEMS = 100

READ = ToolAnnotations(read_only_hint=True, open_world_hint=True)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=True)

INSTRUCTIONS = f"""\
Tools for the PacketFabric NaaS API (ports, virtual circuits, cloud routers, cloud
connections, locations, pricing, metrics, billing, marketplace).

Workflow:
- Prefer the curated pf_* tools for common reads (account, ports, services, cloud routers,
  locations, pricing, traffic).
- For anything else: pf_search_endpoints -> pf_describe_endpoint -> pf_call_endpoint.
- Circuit IDs look like PF-AP-XXX-1234 (ports), PF-BC-XXX-XXX-1234 (VCs), PF-L3-CUST-1234
  (cloud routers). Locations use POP codes like LAX1, DAL2, NYC5.
- Responses are trimmed: use `fields` and `max_items` on pf_call_endpoint to keep lists small.
- pf_get_pricing and pf_find_locations work without an API key (list pricing only). Every other
  call needs the user's own PacketFabric API key.

Writes (create/update/delete, which can create billable services) are
{"ENABLED" if ALLOW_WRITES else "DISABLED on this server (PF_ALLOW_WRITES is not set)"}.
{"Before calling a write with confirm=true, call it once without confirm to get the preview, show the user exactly what will be sent, and get their explicit approval." if ALLOW_WRITES else ""}
"""



async def _caller_auth_middleware(ctx: Any, call_next: Any) -> Any:
    """Over HTTP, bind the caller's own PacketFabric credentials (Authorization: Bearer ...)
    to this request so tool calls run as them. No-op on stdio (no headers)."""
    request = getattr(ctx, "request", None)  # Starlette Request over HTTP, None on stdio
    creds = credentials_from_headers(getattr(request, "headers", None) or getattr(ctx, "headers", None))
    if creds is None:
        return await call_next(ctx)
    token = caller_credentials.set(creds)
    try:
        return await call_next(ctx)
    finally:
        caller_credentials.reset(token)


mcp = MCPServer(
    "packetfabric",
    title=metadata.TITLE,
    description=metadata.DESCRIPTION,
    version=metadata.VERSION,
    website_url=metadata.REPOSITORY_URL,
    instructions=INSTRUCTIONS,
    middleware=[_caller_auth_middleware],
)

_spec: Spec | None = None
_client: PacketFabricClient | None = None


def spec() -> Spec:
    global _spec
    if _spec is None:
        _spec = Spec.load()
    return _spec


def client() -> PacketFabricClient:
    global _client
    if _client is None:
        _client = PacketFabricClient(spec().base_url)
    return _client


# ---------------------------------------------------------------- helpers


def _dump(obj: Any) -> str:
    return json.dumps(obj, indent=1, default=str, ensure_ascii=False)


def _project(item: Any, fields: list[str] | None) -> Any:
    if not fields or not isinstance(item, dict):
        return item
    out = {}
    for f in fields:
        cur: Any = item
        for part in f.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        out[f] = cur
    return out


def _shape(data: Any, fields: list[str] | None, max_items: int) -> tuple[Any, dict[str, Any]]:
    meta: dict[str, Any] = {}
    container_key = None
    items = None
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        # Common paginated envelopes: {"results": [...]}, {"data": [...]}, {"items": [...]}
        for key in ("results", "data", "items"):
            if isinstance(data.get(key), list):
                container_key, items = key, data[key]
                break
    if items is None:
        return _project(data, fields), meta

    meta["total_items"] = len(items)
    if len(items) > max_items:
        meta["truncated_to"] = max_items
        meta["hint"] = "Narrow with filters/pagination params, or raise max_items."
        items = items[:max_items]
    items = [_project(i, fields) for i in items]
    if container_key:
        rest = {k: v for k, v in data.items() if k not in (container_key, "_links")}
        return {**rest, container_key: items}, meta
    return items, meta


def _suggest(op_id: str) -> str:
    hits = spec().search(op_id.replace("_", " "), limit=5)
    if not hits:
        return ""
    return " Did you mean: " + ", ".join(h.operation_id for h in hits) + "?"


def _split_args(op: Operation, params: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    known = {p.name: p for p in op.params}
    path_p, query_p, unknown = {}, {}, []
    for k, v in params.items():
        p = known.get(k)
        if p is None:
            unknown.append(k)
            query_p[k] = v  # pass through; the API may accept undocumented filters
        elif p.location == "path":
            path_p[k] = v
        elif p.location == "query":
            query_p[k] = v
    return path_p, query_p, unknown


async def _execute(
    op: Operation,
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    body: Any = None,
    fields: list[str] | None = None,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> str:
    try:
        r = await client().request(op, path_params, query, body)
    except PFError as e:
        raise ToolError(str(e)) from e
    except Exception as e:  # network errors etc.
        raise ToolError(f"Request to PacketFabric failed: {type(e).__name__}: {e}") from e

    ctype = r.headers.get("content-type", "")
    if r.status_code >= 400:
        detail: Any
        try:
            detail = r.json()
        except Exception:
            detail = r.text[:2000]
        err: dict[str, Any] = {"status": r.status_code, "operation_id": op.operation_id, "error": detail}
        if r.status_code == 401:
            err["hint"] = "Credentials rejected. Check the API key (Authorization header, or PF_TOKEN / PF_LOGIN+PF_PASSWORD for local use)."
        elif r.status_code == 403:
            err["hint"] = "Authenticated, but this user/key lacks permission for this endpoint."
        raise ToolError(_dump(err))

    if r.status_code == 204 or not r.content:
        return _dump({"status": r.status_code, "ok": True})

    if "json" in ctype:
        data, meta = _shape(r.json(), fields, max_items)
        text = _dump({**({"_meta": meta} if meta else {}), "data": data}) if meta else _dump(data)
    else:
        text = r.text

    if len(text) > MAX_CHARS:
        text = (
            text[:MAX_CHARS]
            + f"\n…[truncated at {MAX_CHARS} chars of {len(text)}; use `fields`, `max_items`, or filters]"
        )
    return text


async def _run(op_id: str, fields: list[str] | None = None, max_items: int = DEFAULT_MAX_ITEMS, **params: Any) -> str:
    op = spec().get(op_id)
    if op is None:  # spec drifted
        raise ToolError(f"Operation {op_id} not found in the bundled spec. Run `packetfabric-mcp --update-spec`.")
    path_p, query_p, _ = _split_args(op, {k: v for k, v in params.items() if v is not None})
    return await _execute(op, path_p, query_p, None, fields, max_items)


Fields = Annotated[
    list[str] | None,
    Field(description="Only return these keys from each item (dot paths allowed, e.g. 'interfaces'). Omit for all."),
]
MaxItems = Annotated[int, Field(ge=1, le=5000, description="Cap on list items returned.")]

# ---------------------------------------------------------------- discovery tools


@mcp.tool(annotations=READ)
def pf_list_api_areas() -> str:
    """List the areas (tags) of the PacketFabric API with counts of read and write operations.

    Use this to orient yourself before pf_search_endpoints."""
    return _dump({"writes_enabled": ALLOW_WRITES, "areas": spec().tags()})


@mcp.tool(annotations=READ)
def pf_search_endpoints(
    query: Annotated[str, Field(description="Keywords, e.g. 'cloud router bgp', 'port metrics', 'aws hosted'.")] = "",
    tag: Annotated[str | None, Field(description="Restrict to one API area from pf_list_api_areas.")] = None,
    read_only: Annotated[bool | None, Field(description="True = only safe reads, False = only writes.")] = None,
    limit: Annotated[int, Field(ge=1, le=100)] = 25,
) -> str:
    """Search all PacketFabric API endpoints by keyword. Returns operation_ids to pass to
    pf_describe_endpoint / pf_call_endpoint."""
    hits = spec().search(query, tag=tag, read_only=read_only, limit=limit)
    return _dump({"count": len(hits), "results": [h.brief() for h in hits]})


@mcp.tool(annotations=READ)
def pf_describe_endpoint(operation_id: str) -> str:
    """Show parameters, request body schema and response shape for one endpoint.
    Call this before pf_call_endpoint for anything you haven't used yet."""
    op = spec().get(operation_id)
    if op is None:
        raise ToolError(f"Unknown operation_id '{operation_id}'.{_suggest(operation_id)}")
    d = spec().describe(op)
    if not op.is_read_only:
        d["note"] = (
            "Write operation." if ALLOW_WRITES else "Write operation — disabled on this server (PF_ALLOW_WRITES unset)."
        )
    text = _dump(d)
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + "\n…[truncated]"
    return text


@mcp.tool(annotations=WRITE if ALLOW_WRITES else READ)
async def pf_call_endpoint(
    operation_id: Annotated[str, Field(description="From pf_search_endpoints.")],
    params: Annotated[
        dict[str, Any] | None,
        Field(description="Path and query parameters by name, e.g. {'port_circuit_id': 'PF-AP-LAX1-1234', 'since': '1 day ago'}. Lists are sent as repeated query params."),
    ] = None,
    body: Annotated[Any, Field(description="JSON request body for POST/PUT/PATCH.")] = None,
    confirm: Annotated[
        bool,
        Field(description="Required true to actually execute a write. Without it, writes return a preview only."),
    ] = False,
    fields: Fields = None,
    max_items: MaxItems = DEFAULT_MAX_ITEMS,
) -> str:
    """Call any PacketFabric API endpoint by operation_id.

    Reads run immediately. Writes (create/modify/delete — may create billable services)
    are only possible when the server was started with PF_ALLOW_WRITES=true, and return a
    dry-run preview unless confirm=true. Always show the user the preview and get explicit
    approval before re-calling with confirm=true."""
    op = spec().get(operation_id)
    if op is None:
        raise ToolError(f"Unknown operation_id '{operation_id}'.{_suggest(operation_id)}")
    path_p, query_p, unknown = _split_args(op, params or {})

    if not op.is_read_only:
        preview = {
            "dry_run": True,
            "operation_id": op.operation_id,
            "request": f"{op.method.upper()} {op.path}",
            "path_params": path_p,
            "query": query_p,
            "body": body,
            "summary": op.summary,
        }
        if unknown:
            preview["warning_unknown_params"] = unknown
        if not ALLOW_WRITES:
            raise ToolError(
                "Writes are disabled on this server. To enable, restart it with PF_ALLOW_WRITES=true. "
                "Request that would have been sent:\n" + _dump(preview)
            )
        if not confirm:
            preview["next_step"] = "Show this to the user. If they approve, call again with confirm=true."
            return _dump(preview)

    result = await _execute(op, path_p, query_p, body, fields, max_items)
    if unknown:
        result = f"(note: params not in spec, sent as query: {unknown})\n" + result
    return result


# ---------------------------------------------------------------- curated read tools


@mcp.tool(annotations=READ)
async def pf_get_account() -> str:
    """Get the current PacketFabric customer account (name, account number, UUID, type).
    Good first call to confirm credentials work."""
    return await _run("customer_get")


@mcp.tool(annotations=READ)
async def pf_list_ports(
    q: Annotated[str | None, Field(description="Free-text filter: description, circuit id, POP, region.")] = None,
    pop: Annotated[str | None, Field(description="POP code, e.g. LAX1.")] = None,
    market: Annotated[str | None, Field(description="Market code, e.g. LAX, NYC.")] = None,
    is_lag: bool | None = None,
    is_cloud: bool | None = None,
    is_ptp: bool | None = None,
    fields: Fields = None,
    max_items: MaxItems = DEFAULT_MAX_ITEMS,
) -> str:
    """List the account's ports (physical access ports, LAGs, cloud ports) with speed, status, POP."""
    return await _run(
        "get_port_list", fields, max_items,
        q=q, pop=pop, market=market, is_lag=is_lag, is_cloud=is_cloud, is_ptp=is_ptp,
    )  # fmt: skip


@mcp.tool(annotations=READ)
async def pf_get_port(port_circuit_id: str) -> str:
    """Get full details for one port by circuit id (e.g. PF-AP-LAX1-1234)."""
    return await _run("get_port", port_circuit_id=port_circuit_id)


@mcp.tool(annotations=READ)
async def pf_list_services(
    q: Annotated[str | None, Field(description="Free-text filter: description, VC circuit id, interface POP/port.")] = None,
    port_circuit_id: Annotated[str | None, Field(description="Only VCs on this port.")] = None,
    service_type: Annotated[
        list[
            Literal[
                "backbone", "cloud_dedicated", "cloud_hosted", "cr_connection", "ix",
                "marketplace_cloud_dedicated", "marketplace_cloud_hosted", "ptp", "test", "marketplace",
            ]
        ]
        | None,
        Field(description="Filter by one or more service types."),
    ] = None,
    fields: Fields = None,
    max_items: MaxItems = DEFAULT_MAX_ITEMS,
) -> str:
    """List the account's virtual circuits / services (backbone VCs, cloud connections, IX, marketplace)."""
    return await _run(
        "get_service_list", fields, max_items, q=q, port_circuit_id=port_circuit_id, service_type=service_type
    )


@mcp.tool(annotations=READ)
async def pf_list_point_to_point(
    q: str | None = None, fields: Fields = None, max_items: MaxItems = DEFAULT_MAX_ITEMS
) -> str:
    """List point-to-point (wavelength-style) services."""
    return await _run("ptplist", fields, max_items, q=q)


@mcp.tool(annotations=READ)
async def pf_list_cloud_routers(fields: Fields = None, max_items: MaxItems = DEFAULT_MAX_ITEMS) -> str:
    """List Cloud Routers (L3 NaaS routers) on the account with ASN, capacity, regions."""
    return await _run("cloud_routers_list", fields, max_items)


@mcp.tool(annotations=READ)
async def pf_list_cloud_router_connections(
    cloud_router_circuit_id: Annotated[
        str | None, Field(description="Only connections on this Cloud Router (PF-L3-CUST-…). Omit for all.")
    ] = None,
    fields: Fields = None,
    max_items: MaxItems = DEFAULT_MAX_ITEMS,
) -> str:
    """List Cloud Router connections (AWS/Azure/GCP/Oracle/IBM, ports, IPsec) across the account or for one router."""
    if cloud_router_circuit_id:
        return await _run("cloud_routers_connections", fields, max_items, circuit_id=cloud_router_circuit_id)
    return await _run("cloud_routers_connections_by_customer", fields, max_items)


@mcp.tool(annotations=READ)
async def pf_list_cloud_connections(
    kind: Literal["hosted", "dedicated"] = "hosted",
    q: str | None = None,
    fields: Fields = None,
    max_items: MaxItems = DEFAULT_MAX_ITEMS,
) -> str:
    """List Layer-2 cloud connections (hosted or dedicated) to AWS, Azure, Google, Oracle, IBM."""
    if kind == "hosted":
        return await _run("get_connections_hosted_list", fields, max_items, q=q)
    return await _run("get_connections_dedicated_list", fields, max_items)


@mcp.tool(annotations=READ)
async def pf_find_locations(
    pop: Annotated[str | None, Field(description="POP code, e.g. LAX1.")] = None,
    city: str | None = None,
    state: str | None = None,
    market: Annotated[str | None, Field(description="Market code, e.g. LAX.")] = None,
    region: Annotated[str | None, Field(description="Region short name, e.g. US, UK.")] = None,
    any_type: Annotated[
        bool | None,
        Field(description="Include non-primary location types (campus, metro extension). Defaults to true when `pop` is given."),
    ] = None,
    near_cloud_router: bool | None = None,
    ipsec_capable: bool | None = None,
    nat_capable: bool | None = None,
    fields: Fields = None,
    max_items: MaxItems = DEFAULT_MAX_ITEMS,
) -> str:
    """Find PacketFabric locations / POPs (data center, address, market, status, port types).
    Works without an API key."""
    if pop and any_type is None:
        # The API returns only primary sites by default, and many POPs exist only as campus or
        # metro-extension sites, so a lookup by POP code would otherwise come back empty.
        any_type = True
    return await _run(
        "get_location_list", fields or ["pop", "type", "market", "site", "city", "state", "country", "status", "vendor"],
        max_items, pop=pop, city=city, state=state, market=market, region=region, any_type=any_type,
        near_cloud_router=near_cloud_router, ipsec_capable=ipsec_capable, nat_capable=nat_capable,
    )  # fmt: skip


@mcp.tool(annotations=READ)
async def pf_get_pricing(
    product_type: Literal[
        "aggregate_capacity", "cloud_dedicated", "cloud_dedicated_vc", "cloud_hosted", "crossconnect",
        "pointtopoint", "port", "port_enni", "vcbwc", "cloud_router", "cr_connection", "vc_ix",
        "vc_marketplace", "add_on_fee", "high_performance_internet", "ip_subnet", "alert_credits",
    ],
    location_type: Literal["site", "pop", "market", "country", "region"] = "pop",
    side_a: Annotated[str | None, Field(description="A-side location code, e.g. LAX1 (or market/region per location_type).")] = None,
    side_z: Annotated[str | None, Field(description="Z-side location code, e.g. NYC5.")] = None,
    speed: Annotated[str | None, Field(description="e.g. 1Gbps, 10Gbps, 100Gbps.")] = None,
    subscription_term: Annotated[Literal[1, 12, 24, 36] | None, Field(description="Months.")] = None,
    service_class: Annotated[str | None, Field(description="'metro' or 'longhaul'.")] = None,
    media: Annotated[str | None, Field(description="Optic media, e.g. LR, LR4.")] = None,
    max_items: MaxItems = DEFAULT_MAX_ITEMS,
) -> str:
    """Look up list pricing (MRC/NRC) for a PacketFabric product between locations. Read-only, no order is created.
    vcbwc = backbone virtual circuit bandwidth. Works without an API key."""
    return await _run(
        "get_pricing", None, max_items, product_type=product_type, location_type=location_type,
        side_a=side_a, side_z=side_z, speed=speed, subscription_term=subscription_term,
        service_class=service_class, media=media,
    )  # fmt: skip


@mcp.tool(annotations=READ)
async def pf_get_traffic(
    port_circuit_id: Annotated[str, Field(description="Port circuit id, e.g. PF-AP-LAX1-1234.")],
    vc_circuit_id: Annotated[
        str | None, Field(description="If given, traffic for this VC on that port instead of the whole port.")
    ] = None,
    type: Literal["bps", "pps"] = "bps",
    since: Annotated[str, Field(description="Relative start, e.g. '24 hours ago', '7 days ago'.")] = "24 hours ago",
    until: str = "now",
    interval: Annotated[int | None, Field(description="Bucket size in seconds, e.g. 300, 3600.")] = None,
) -> str:
    """Traffic rate time series for a port (or one VC on a port)."""
    if vc_circuit_id:
        return await _run(
            "ifl_rate", None, 5000, vc_circuit_id=vc_circuit_id, port_circuit_id=port_circuit_id,
            type=type, since=since, until=until, interval=interval,
        )  # fmt: skip
    return await _run(
        "ifd_rate", None, 5000, port_circuit_id=port_circuit_id, type=type, since=since, until=until, interval=interval
    )


@mcp.tool(annotations=READ)
async def pf_get_maintenances(
    pop: Annotated[str | None, Field(description="POP name, e.g. LAX1.")] = None,
    market: Annotated[str | None, Field(description="Market code, e.g. LAX.")] = None,
    max_items: MaxItems = DEFAULT_MAX_ITEMS,
) -> str:
    """Current and upcoming maintenance windows, optionally for a POP or market."""
    return await _run("maintenances_by_location", None, max_items, pop_names_list=pop, market_codes_list=market)
