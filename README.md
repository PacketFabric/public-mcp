# packetfabric-mcp

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
uv run pytest            # 13 offline tests
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

## Other

- Refresh the bundled spec: `uv run packetfabric-mcp --update-spec`
- Run as a remote HTTP server: `uv run packetfabric-mcp --http --host 0.0.0.0 --port 8765` (serves `/mcp`).
  Note there's no auth in front of it — put it behind something that has auth before exposing it.
- To add a curated tool, copy one of the `pf_list_*` functions in `server.py` and point `_run()` at an
  `operation_id` (find one with `pf_search_endpoints`).
