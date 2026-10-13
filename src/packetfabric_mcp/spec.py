"""Load the PacketFabric OpenAPI spec and index its operations for search/describe/call."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import cached_property
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

try:  # libyaml is ~10x faster on this 900 KB spec
    from yaml import CSafeLoader as _Loader
except ImportError:  # pragma: no cover
    from yaml import SafeLoader as _Loader  # type: ignore[assignment]

SPEC_URL = "https://api.packetfabric.com/openapi/specification/swagger.yaml"
HTTP_METHODS = ("get", "post", "put", "patch", "delete")

# POST endpoints that only compute/check and never create or change anything.
SAFE_POST_OPERATIONS = {
    "modify_order_preview",
    "check_bgp_address_uniqueness",
}

# Endpoints that are never exposed: they manage the caller's own credentials/session
# or sign up new accounts, and have no business being driven by an LLM.
BLOCKED_TAGS = {"Authentication", "Multi-Factor Authentication", "Signup", "TeamSignup", "API keys"}


@dataclass
class Param:
    name: str
    location: str  # path | query | header
    required: bool
    type: str | None
    description: str
    enum: list[Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "in": self.location, "required": self.required}
        if self.type:
            d["type"] = self.type
        if self.enum:
            d["enum"] = self.enum
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class Operation:
    operation_id: str
    method: str
    path: str
    summary: str
    description: str
    tags: list[str]
    params: list[Param]
    raw: dict[str, Any] = field(repr=False)
    deprecated: bool = False

    @property
    def is_read_only(self) -> bool:
        return self.method == "get" or self.operation_id in SAFE_POST_OPERATIONS

    @property
    def is_blocked(self) -> bool:
        return bool(set(self.tags) & BLOCKED_TAGS)

    @property
    def tag(self) -> str:
        return self.tags[0] if self.tags else "Other"

    @cached_property
    def search_text(self) -> str:
        parts = [self.operation_id, self.path, self.summary, self.description, " ".join(self.tags)]
        return " ".join(parts).lower()

    def brief(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "method": self.method.upper(),
            "path": self.path,
            "summary": self.summary,
            "tag": self.tag,
            "read_only": self.is_read_only,
        }


def _slug(method: str, path: str) -> str:
    s = re.sub(r"[{}]", "", path.strip("/"))
    s = re.sub(r"[^A-Za-z0-9]+", "_", s)
    return f"{method}_{s}".lower()


def _clean(text: str | None, limit: int | None = None) -> str:
    t = re.sub(r"\s+", " ", (text or "")).strip()
    if limit and len(t) > limit:
        t = t[: limit - 1] + "…"
    return t


class Spec:
    def __init__(self, doc: dict[str, Any]):
        self.doc = doc
        self.operations: dict[str, Operation] = {}
        self._index()

    # ---------- loading ----------
    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "Spec":
        path = path or os.environ.get("PF_SPEC_PATH")
        if path:
            text = Path(path).read_text()
        else:
            text = resources.files("packetfabric_mcp").joinpath("data/openapi.yaml").read_text()
        return cls(yaml.load(text, Loader=_Loader))

    @property
    def base_url(self) -> str:
        servers = self.doc.get("servers") or [{"url": "https://api.packetfabric.com"}]
        return servers[0]["url"].rstrip("/")

    # ---------- $ref resolution ----------
    def resolve(self, node: Any) -> Any:
        seen = 0
        while isinstance(node, dict) and "$ref" in node and seen < 20:
            ref = node["$ref"]
            if not ref.startswith("#/"):
                return node
            target: Any = self.doc
            for key in ref[2:].split("/"):
                target = target[key.replace("~1", "/").replace("~0", "~")]
            node = target
            seen += 1
        return node

    def _index(self) -> None:
        used: set[str] = set()
        for path, item in (self.doc.get("paths") or {}).items():
            shared = item.get("parameters", [])
            for method in HTTP_METHODS:
                op = item.get(method)
                if not op:
                    continue
                op_id = op.get("operationId") or _slug(method, path)
                op_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", op_id)
                if op_id in used:
                    op_id = _slug(method, path)
                used.add(op_id)

                params: list[Param] = []
                seen_names: set[tuple[str, str]] = set()
                for p in [*op.get("parameters", []), *shared]:  # op-level overrides path-level
                    p = self.resolve(p)
                    key = (p.get("name"), p.get("in"))
                    if key in seen_names or p.get("in") == "cookie":
                        continue
                    seen_names.add(key)
                    schema = self.resolve(p.get("schema") or {})
                    ptype = schema.get("type")
                    enum = schema.get("enum")
                    if ptype == "array":
                        items = self.resolve(schema.get("items") or {})
                        ptype = f"array<{items.get('type', 'any')}>"
                        enum = items.get("enum")
                    params.append(
                        Param(
                            name=p["name"],
                            location=p["in"],
                            required=bool(p.get("required") or p["in"] == "path"),
                            type=ptype,
                            description=_clean(p.get("description"), 300),
                            enum=enum,
                        )
                    )

                self.operations[op_id] = Operation(
                    operation_id=op_id,
                    method=method,
                    path=path,
                    summary=_clean(op.get("summary"), 200),
                    description=_clean(op.get("description")),
                    tags=list(op.get("tags") or []),
                    params=params,
                    raw=op,
                    deprecated=bool(op.get("deprecated")),
                )

    # ---------- queries ----------
    def visible(self) -> list[Operation]:
        return [o for o in self.operations.values() if not o.is_blocked]

    def get(self, operation_id: str) -> Operation | None:
        op = self.operations.get(operation_id)
        return None if (op is None or op.is_blocked) else op

    def tags(self) -> list[dict[str, Any]]:
        descs = {t["name"]: _clean(t.get("description"), 160) for t in self.doc.get("tags", [])}
        counts: dict[str, dict[str, int]] = {}
        for o in self.visible():
            c = counts.setdefault(o.tag, {"read": 0, "write": 0})
            c["read" if o.is_read_only else "write"] += 1
        return [
            {"tag": t, "description": descs.get(t, ""), "read_ops": c["read"], "write_ops": c["write"]}
            for t, c in sorted(counts.items())
        ]

    def search(
        self,
        query: str = "",
        tag: str | None = None,
        method: str | None = None,
        read_only: bool | None = None,
        limit: int = 25,
    ) -> list[Operation]:
        terms = [t for t in re.split(r"[\s,/_-]+", query.lower()) if t]
        results: list[tuple[float, Operation]] = []
        for o in self.visible():
            if tag and o.tag.lower() != tag.lower() and tag.lower() not in (t.lower() for t in o.tags):
                continue
            if method and o.method != method.lower():
                continue
            if read_only is not None and o.is_read_only != read_only:
                continue
            if not terms:
                results.append((0.0, o))
                continue
            score = 0.0
            for term in terms:
                if term in o.operation_id.lower():
                    score += 3
                if term in o.path.lower():
                    score += 2
                if term in o.summary.lower():
                    score += 2
                if term in o.tag.lower():
                    score += 1.5
                if term in o.search_text:
                    score += 1
                else:
                    score -= 2  # every term should appear somewhere
            if score > 0:
                if o.deprecated:
                    score -= 1
                results.append((score, o))
        results.sort(key=lambda x: (-x[0], x[1].path, x[1].method))
        return [o for _, o in results[:limit]]

    # ---------- schema rendering ----------
    def compact_schema(self, node: Any, depth: int = 0, max_depth: int = 4, _stack: tuple = ()) -> Any:
        """Render a JSON schema compactly: resolve refs, drop noise, cap depth/recursion."""
        ref = node.get("$ref") if isinstance(node, dict) else None
        if ref and ref in _stack:
            return f"<recursive {ref.rsplit('/', 1)[-1]}>"
        stack = (*_stack, ref) if ref else _stack
        node = self.resolve(node)
        if not isinstance(node, dict):
            return node
        if depth > max_depth:
            return node.get("type", "object") + " …"

        for combo in ("allOf", "oneOf", "anyOf"):
            if combo in node:
                parts = [self.compact_schema(s, depth, max_depth, stack) for s in node[combo]]
                if combo == "allOf":
                    merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
                    for p in parts:
                        if isinstance(p, dict):
                            merged["properties"].update(p.get("properties", {}))
                            merged["required"] += p.get("required", [])
                    if not merged["required"]:
                        merged.pop("required")
                    return merged
                return {combo: parts}

        out: dict[str, Any] = {}
        t = node.get("type")
        if t:
            out["type"] = t
        for k in ("format", "enum", "default", "minimum", "maximum", "nullable", "readOnly"):
            if k in node:
                out[k] = node[k]
        if node.get("description") and depth > 0:
            out["description"] = _clean(node["description"], 200)
        if "example" in node and not isinstance(node["example"], (dict, list)):
            out["example"] = node["example"]
        if t == "array" or "items" in node:
            out["items"] = self.compact_schema(node.get("items", {}), depth + 1, max_depth, stack)
        if "properties" in node:
            out["properties"] = {
                k: self.compact_schema(v, depth + 1, max_depth, stack)
                for k, v in node["properties"].items()
                if k != "_links"
            }
            if node.get("required"):
                out["required"] = node["required"]
        return out

    def describe(self, op: Operation) -> dict[str, Any]:
        raw = op.raw
        body = None
        rb = self.resolve(raw.get("requestBody") or {})
        if rb:
            content = rb.get("content", {})
            media = content.get("application/json") or next(iter(content.values()), {})
            body = {
                "required": bool(rb.get("required")),
                "content_type": "application/json" if "application/json" in content else next(iter(content), None),
                "schema": self.compact_schema(media.get("schema", {})),
            }
            if "example" in media:
                body["example"] = media["example"]

        responses = {}
        for code, resp in (raw.get("responses") or {}).items():
            resp = self.resolve(resp)
            entry: dict[str, Any] = {"description": _clean(resp.get("description"), 160)}
            if str(code).startswith("2"):
                content = resp.get("content") or {}
                media = content.get("application/json")
                if media and media.get("schema"):
                    entry["schema"] = self.compact_schema(media["schema"], max_depth=2)
                elif content:
                    entry["content_type"] = next(iter(content))
            responses[str(code)] = entry

        return {
            **op.brief(),
            "description": op.description,
            "deprecated": op.deprecated,
            "parameters": [p.to_dict() for p in op.params if p.location != "header"],
            "request_body": body,
            "responses": responses,
        }
