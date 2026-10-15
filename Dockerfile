# Hosted (multi-user) deployment: MCP + discovery + A2A over HTTP on :8765.
# Callers authenticate with their own PacketFabric API key; set PF_PUBLIC_URL to the
# public https:// base URL so the discovery documents advertise the right endpoints.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --extra a2a
ENV PF_PORT=8765
EXPOSE 8765
USER nobody
CMD ["/app/.venv/bin/packetfabric-mcp", "--http", "--host", "0.0.0.0"]
