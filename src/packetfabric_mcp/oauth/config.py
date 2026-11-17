from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from .. import metadata

DEFAULT_PORTAL_ORIGINS: tuple[str, ...] = (
    "https://portal.packetfabric.com",
    "https://portal-beta.packetfabric.com",
    "https://*.portal.packetfabric.com",
)
# Entries ending in "://" allow any redirect URI with that scheme; all others
# must match the whole URI exactly. Loopback redirects are always allowed.
DEFAULT_ALLOWED_REDIRECTS: tuple[str, ...] = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://vscode.dev/redirect",
    "cursor://",
    "vscode://",
    "vscode-insiders://",
)
DEFAULT_KEY_TTL_SECONDS = 2_592_000

_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
_LABEL = re.compile(r"[A-Za-z0-9-]+")
# urlsplit silently strips whitespace/control characters and browsers treat "\\" as "/",
# so anything outside printable ASCII (or containing a backslash) is refused before parsing.
_UNSAFE = re.compile(r"[^\x21-\x7e]|\\")


def _csv(name: str) -> tuple[str, ...]:
    return tuple(p for p in (s.strip() for s in os.environ.get(name, "").split(",")) if p)


@dataclass(frozen=True)
class OAuthConfig:
    secrets: tuple[str, ...]
    public_url: str
    portal_url: str
    portal_origins: tuple[str, ...]
    allowed_redirects: tuple[str, ...]
    key_ttl_seconds: int

    @property
    def resource_url(self) -> str:
        return self.public_url + metadata.MCP_PATH

    @classmethod
    def from_env(cls, public_url: str | None) -> OAuthConfig | None:
        secrets = _csv("PF_OAUTH_SECRET")
        portal_url = os.environ.get("PF_PORTAL_URL", "").strip()
        if not secrets or not portal_url:
            return None
        public_url = (public_url or os.environ.get("PF_PUBLIC_URL", "")).strip()
        if not public_url:
            raise ValueError("PF_PUBLIC_URL is required when OAuth sign-in is enabled")
        ttl = os.environ.get("PF_OAUTH_KEY_TTL_SECONDS", "").strip()
        return cls(
            secrets=secrets,
            public_url=public_url.rstrip("/"),
            portal_url=portal_url.rstrip("/"),
            portal_origins=_csv("PF_PORTAL_ORIGINS") or DEFAULT_PORTAL_ORIGINS,
            allowed_redirects=_csv("PF_OAUTH_ALLOWED_REDIRECTS") or DEFAULT_ALLOWED_REDIRECTS,
            key_ttl_seconds=int(ttl) if ttl else DEFAULT_KEY_TTL_SECONDS,
        )


def _parse(value: str) -> SplitResult | None:
    try:
        parts = urlsplit(value)
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return None
    return parts


def _host_matches(pattern: str, host: str) -> bool:
    p_labels, h_labels = pattern.lower().split("."), host.lower().split(".")
    if len(p_labels) != len(h_labels):
        return False
    return all(
        _LABEL.fullmatch(h) is not None if p == "*" else p == h
        for p, h in zip(p_labels, h_labels)
    )


def origin_allowed(origin: str | None, patterns: Sequence[str]) -> bool:
    if not origin or origin == "null" or _UNSAFE.search(origin):
        return False
    o = _parse(origin)
    if o is None or not o.scheme or not o.hostname:
        return False
    if o.path or o.query or o.fragment or o.username is not None or o.password is not None:
        return False
    for pattern in patterns:
        p = _parse(pattern)
        if p is None or not p.hostname:
            continue
        if (
            o.scheme == p.scheme
            and o.port == p.port
            and _host_matches(p.hostname, o.hostname)
        ):
            return True
    return False


def redirect_allowed(uri: str, allowed: Sequence[str]) -> bool:
    if _UNSAFE.search(uri):
        return False
    u = _parse(uri)
    if u is None or u.fragment or "#" in uri or not u.scheme:
        return False
    if u.username is not None or u.password is not None:
        return False
    if u.scheme in ("http", "https") and u.hostname in _LOOPBACK_HOSTS:
        return True
    for entry in allowed:
        if entry.endswith("://"):
            if u.scheme == entry[:-3].lower() and uri.lower().startswith(entry.lower()):
                return True
        elif uri == entry:
            return True
    return False


def redirect_display(uri: str) -> str:
    u = urlsplit(uri)
    if u.scheme in ("http", "https"):
        return u.netloc.rpartition("@")[2]
    return f"{u.scheme}://"
