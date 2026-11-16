# packetfabric-mcp

<!-- mcp-name: io.github.PacketFabric/packetfabric-mcp -->

MCP server for the [PacketFabric API](https://docs.packetfabric.com/api/v2/), built from its OpenAPI spec
(346 operations, bundled in `src/packetfabric_mcp/data/openapi.yaml`).

Instead of one tool per endpoint (which overwhelms the model), it exposes **16 tools**:

| Tool | What it does |
|---|---|
| `pf_get_account` | Current customer account — good credential check |
| `pf_list_ports`, `pf_get_port` | Ports / LAGs / cloud ports |
| `pf_list_services` | Virtual circuits (backbone, cloud, IX, marketplace) |
| `pf_list_point_to_point` | PTP services |
| `pf_list_cloud_routers`, `pf_list_cloud_router_connections` | Cloud Routers and their connections |
| `pf_list_cloud_connections` | L2 hosted / dedicated cloud connections |
| `pf_find_locations` | POPs / data centers |
| `pf_get_pricing` | List pricing (MRC/NRC) between locations |
| `pf_get_traffic` | bps/pps time series for a port or a VC on a port |
| `pf_get_maintenances` | Current/upcoming maintenance by POP or market |
| `pf_list_api_areas` → `pf_search_endpoints` → `pf_describe_endpoint` → `pf_call_endpoint` | Reach **any** other endpoint in the spec |

### Safety

- **Read-only by default.** Any POST/PUT/PATCH/DELETE is refused unless the server runs with `PF_ALLOW_WRITES=true`.
- With writes enabled, a write call returns a **dry-run preview** first; it only executes when re-called with `confirm=true`.
- Auth/session, MFA, signup and API-key-management endpoints are never exposed.
- List responses are capped (`max_items`, default 100) and can be trimmed to specific `fields`.

## Setup

Requires [uv](https://docs.astral.sh/uv/) (`brew install uv`).

```sh
cd ~/Documents/src/packetfabric/mcp
uv sync
uv run pytest            # offline tests
```

Get an API key in the PacketFabric portal (Settings → API Keys). API keys work with MFA-enabled accounts;
login/password does not.

### Claude Code

```sh
claude mcp add packetfabric -s user -e PF_TOKEN=your-key -- \
  uv run --directory ~/Documents/src/packetfabric/mcp packetfabric-mcp
```

### Claude Desktop / Cowork

Settings → Developer → Edit Config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "packetfabric": {
      "command": "/opt/homebrew/bin/uv",
      "args": ["run", "--directory", "/Users/chad/Documents/src/packetfabric/mcp", "packetfabric-mcp"],
      "env": { "PF_TOKEN": "your-key" }
    }
  }
}
```

(Use `which uv` for the command path. Restart Claude after editing.)

To allow provisioning, add `"PF_ALLOW_WRITES": "true"` to `env`. Consider a separate server entry
(e.g. `packetfabric-rw`) so read-only stays the default.

## Configuration

| Env var | Purpose |
|---|---|
| `PF_TOKEN` | API key (sent as Bearer). Preferred. |
| `PF_LOGIN` / `PF_PASSWORD` | Alternative to `PF_TOKEN`; auto re-login on 401 |
| `PF_ALLOW_WRITES` | `true` to allow create/modify/delete (each still needs `confirm=true`) |
| `PF_ON_BEHALF` | Resellers: customer UUID sent as `On-Behalf` header |
| `PF_API_URL` | Override base URL (default `https://api.packetfabric.com`) |
| `PF_SPEC_PATH` | Use a different OpenAPI file |
| `PF_TIMEOUT`, `PF_MAX_RESPONSE_CHARS` | HTTP timeout (s, default 60) and response size cap (default 60000) |

## Hosted mode (MCP over HTTP + A2A + discovery)

```sh
uv sync --extra a2a
PF_PUBLIC_URL=https://mcp.example.com uv run packetfabric-mcp --http --host 0.0.0.0 --port 8765
# or: docker build -t packetfabric-mcp . && docker run -p 8765:8765 -e PF_PUBLIC_URL=... packetfabric-mcp
```

| Path | What |
|---|---|
| `POST /mcp` | MCP streamable HTTP (stateless, so it scales horizontally) |
| `GET /mcp/server-card` | [MCP Server Card](https://modelcontextprotocol.io/seps/2127-mcp-server-cards) (SEP-2127) |
| `GET /.well-known/agent-card.json` | [A2A](https://a2a-protocol.org) v1.0 Agent Card |
| `POST /a2a` | A2A JSON-RPC endpoint |
| `GET /.well-known/ai-catalog.json` | [AI Catalog](https://ai-catalog.io) listing both cards |
| `GET /.well-known/agent.json` | Same agent card at the pre-0.3 A2A path, for older clients |
| `GET /llms.txt` | Summary and links for language models ([llmstxt.org](https://llmstxt.org)) |
| `GET /` | Short human-readable page linking to all of the above |
| `GET /healthz` | Liveness |

**Every caller uses their own PacketFabric API key**, sent as `Authorization: Bearer <key>` (plus
`On-Behalf: <customer uuid>` for resellers). The operator's `PF_TOKEN`/`PF_LOGIN` are ignored in HTTP mode
unless `PF_HTTP_USE_SERVER_CREDENTIALS=true`, which is only safe for a private single-user deployment.
Put it behind TLS; the discovery documents are public by design and contain no secrets.

The A2A agent is deterministic, not an LLM: send a DataPart `{"skill": "list_ports", "arguments": {"pop": "LAX1"}}`
and get the API result back as a JSON data artifact. Skills mirror the MCP tools (see the agent card).
A2A access is always read-only. A2A tasks are private to the API key (and `On-Behalf` customer) that created
them; requests without a key get a plain reply and nothing is stored.

```sh
curl -s https://mcp.example.com/a2a -H 'A2A-Version: 1.0' -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $PF_TOKEN" -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":
  {"messageId":"1","role":"ROLE_USER","parts":[{"data":{"skill":"find_locations","arguments":{"market":"NYC"}}}]}}}'
```

| Env var (HTTP mode) | Purpose |
|---|---|
| `PF_PUBLIC_URL` | Public https base URL advertised in the cards (otherwise derived from the request) |
| `PF_HTTP_USE_SERVER_CREDENTIALS` | `true` = fall back to the operator's own credentials (private use only) |
| `PF_DISABLE_A2A` | `true` = serve MCP only |
| `PF_ICON_URL` | Icon advertised in the cards |
| `PF_MAX_BODY_BYTES` | Request body cap for non-MCP routes, including `/a2a` (default 1 MiB, 413 above it) |
| `PF_A2A_TASK_TTL_SECONDS` | How long finished A2A tasks stay retrievable (default 3600) |
| `PF_A2A_MAX_TASKS` / `PF_A2A_MAX_TASKS_PER_CALLER` | Caps on stored A2A tasks, oldest evicted first (defaults 10000 / 200) |

**Domain-level discovery:** if the server runs on its own host (e.g. `mcp.packetfabric.com`), the
`/.well-known/` documents are already in the right place. To advertise it from the main domain, serve a copy of
`/.well-known/ai-catalog.json` from `https://packetfabric.com/.well-known/ai-catalog.json` (the entries hold
absolute URLs, so a static copy works).

## Publishing

Listed on the [MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.PacketFabric/packetfabric-mcp` (see `server.json`), installed from PyPI as `packetfabric-mcp`.

Branches: `dev` (default) takes every change. Each push to it publishes the container image
`ghcr.io/packetfabric/public-mcp:vX.Y.Z-dev.N` (`.github/workflows/image.yml`), and the staging server at
`https://mcp.dev.packetfabric.net` picks the newest one up within minutes. `main` is the release line.

1. Bump the version in `pyproject.toml`, `src/packetfabric_mcp/__init__.py` and `server.json`
   (tests fail if they disagree).
2. Merge `dev` into `main` with a PR, then push a tag `vX.Y.Z` on `main`. `.github/workflows/publish.yml` runs the
   tests, publishes to PyPI (Trusted Publishing), then publishes `server.json` to the MCP Registry using GitHub OIDC.
   `.github/workflows/image.yml` publishes `ghcr.io/packetfabric/public-mcp:vX.Y.Z` and writes its digest to the run
   summary. Both refuse a release tag that is not on `main`; pre-release tags (`vX.Y.ZrcN`) may come from `dev`,
   publish to PyPI only (not the MCP Registry), and build no image.
3. Production (`https://mcp.packetfabric.com`) runs the newest release: it picks up the new `vX.Y.Z` image within
   minutes of `image.yml` publishing it. Pushing a release tag on `main` is therefore a production deploy.
4. The registry entry lists the hosted endpoint `https://mcp.packetfabric.com/mcp` (in `server.json`; the repo
   variable `MCP_PUBLIC_URL` overrides it if set).

One-time: add a PyPI Trusted Publisher for `packetfabric-mcp` (repo `PacketFabric/public-mcp`, workflow
`publish.yml`, environment `pypi`). The `mcp-name:` comment at the top of this README is how the registry verifies
that the PyPI package belongs to this server; keep it.

To publish under `com.packetfabric/...` instead of `io.github.PacketFabric/...`, change `REGISTRY_NAME` in
`metadata.py` and `server.json`, add the DNS TXT record from `mcp-publisher login dns`, and switch the
workflow's login step.

## Other

- Refresh the bundled spec: `uv run packetfabric-mcp --update-spec`
- To add a curated tool, copy one of the `pf_list_*` functions in `server.py` and point `_run()` at an
  `operation_id` (find one with `pf_search_endpoints`). Add a matching entry to `SKILLS` in `a2a_agent.py`.
