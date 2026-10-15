"""Entry point: `packetfabric-mcp` (stdio) or `packetfabric-mcp --http` / `--update-spec`."""

from __future__ import annotations

import argparse
import os
import sys
from importlib import resources


def _update_spec(url: str) -> None:
    import httpx
    import yaml

    r = httpx.get(url, timeout=60, follow_redirects=True)
    r.raise_for_status()
    doc = yaml.safe_load(r.text)
    if not isinstance(doc, dict) or "paths" not in doc:
        sys.exit("Downloaded document doesn't look like an OpenAPI spec; not saving.")
    target = resources.files("packetfabric_mcp").joinpath("data/openapi.yaml")
    with resources.as_file(target) as path:
        path.write_text(r.text)
    print(f"Saved {len(doc['paths'])} paths (API version {doc.get('info', {}).get('version')}) to {path}")


def main() -> None:
    from .spec import SPEC_URL

    ap = argparse.ArgumentParser(prog="packetfabric-mcp", description=__doc__)
    ap.add_argument("--http", action="store_true", help="Serve streamable HTTP instead of stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PF_PORT", "8765")))
    ap.add_argument("--public-url", default=os.environ.get("PF_PUBLIC_URL"),
                    help="Public base URL (e.g. https://mcp.example.com) used in discovery documents")
    ap.add_argument("--update-spec", nargs="?", const=SPEC_URL, metavar="URL",
                    help="Download the latest PacketFabric OpenAPI spec into the package and exit")
    args = ap.parse_args()

    if args.update_spec:
        _update_spec(args.update_spec)
        return

    if args.http:
        import uvicorn

        from .http_app import build_app

        os.environ.setdefault("PF_PORT", str(args.port))
        app = build_app(public_url=args.public_url, bind_host=args.host)
        uvicorn.run(app, host=args.host, port=args.port, proxy_headers=True, forwarded_allow_ips="*")
    else:
        from .server import mcp

        mcp.run()


if __name__ == "__main__":
    main()
