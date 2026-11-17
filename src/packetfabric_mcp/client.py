"""Thin async HTTP client for the PacketFabric API (auth + request plumbing)."""

from __future__ import annotations

import asyncio
import os
from http.cookiejar import CookieJar, DefaultCookiePolicy
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from . import __version__
from .spec import Operation


class PFError(Exception):
    pass


@dataclass(frozen=True)
class CallerCredentials:
    """Credentials supplied by whoever is calling us over HTTP (MCP or A2A)."""

    token: str | None
    on_behalf: str | None = None


# Set per request by the HTTP front ends; unset (None) for stdio.
caller_credentials: ContextVar[CallerCredentials | None] = ContextVar("pf_caller_credentials", default=None)


def credentials_from_headers(headers: Any) -> CallerCredentials | None:
    """Extract `Authorization: Bearer <PF API key>` (+ optional `On-Behalf`) from request headers."""
    if not headers:
        return None
    get = headers.get
    auth = get("authorization") or get("Authorization") or ""
    scheme, _, value = auth.partition(" ")
    token = value.strip() if scheme.lower() == "bearer" and value.strip() else None
    on_behalf = get("on-behalf") or get("On-Behalf") or None
    if not token and not on_behalf:
        return None
    return CallerCredentials(token=token, on_behalf=on_behalf)


class PacketFabricClient:
    def __init__(self, base_url: str):
        self.base_url = os.environ.get("PF_API_URL", base_url).rstrip("/")
        self._token: str | None = os.environ.get("PF_TOKEN") or os.environ.get("PF_API_KEY") or None
        self._login = os.environ.get("PF_LOGIN") or os.environ.get("PF_USER")
        self._password = os.environ.get("PF_PASSWORD")
        self._static_token = self._token is not None
        self._on_behalf = os.environ.get("PF_ON_BEHALF") or None
        # Hosted/multi-user mode: never fall back to the operator's own credentials.
        self.require_caller_token = False
        self._lock = asyncio.Lock()
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(float(os.environ.get("PF_TIMEOUT", "60"))),
            headers={"User-Agent": f"packetfabric-mcp/{__version__}", "Accept": "application/json"},
            # One client serves every caller, so never keep cookies between requests: a session
            # cookie set for one caller would otherwise be sent on the next caller's request.
            cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
        )

    @property
    def auth_mode(self) -> str:
        if self._static_token:
            return "api_key"
        if self._login and self._password:
            return "login"
        return "none"

    async def _ensure_token(self, force: bool = False) -> str:
        if self._static_token:
            return self._token  # type: ignore[return-value]
        if self._token and not force:
            return self._token
        if not (self._login and self._password):
            raise PFError(
                "No PacketFabric credentials configured. Set PF_TOKEN (an API key from the portal: "
                "Settings > API Keys) or PF_LOGIN + PF_PASSWORD."
            )
        async with self._lock:
            if self._token and not force:
                return self._token
            r = await self._http.post("/v2/auth/login", json={"login": self._login, "password": self._password})
            if r.status_code >= 400:
                raise PFError(f"PacketFabric login failed ({r.status_code}): {r.text[:300]}")
            data = r.json()
            if data.get("mfa_required") or ("token" not in data and "mfa" in str(data).lower()):
                raise PFError("This account requires MFA; use an API key (PF_TOKEN) instead of login/password.")
            self._token = data["token"]
            return self._token

    def _headers(self, token: str) -> dict[str, str]:
        h = {"Authorization": f"Bearer {token}"}
        if self._on_behalf:
            h["On-Behalf"] = self._on_behalf
        return h

    async def request(
        self,
        op: Operation,
        path_params: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        body: Any = None,
    ) -> httpx.Response:
        path_params = {k: v for k, v in (path_params or {}).items() if v is not None}
        missing = [p.name for p in op.params if p.location == "path" and p.name not in path_params]
        if missing:
            raise PFError(f"Missing required path parameter(s) for {op.operation_id}: {', '.join(missing)}")
        path = op.path
        for k, v in path_params.items():
            path = path.replace("{" + k + "}", quote(str(v), safe=""))
        if "{" in path:
            raise PFError(f"Unfilled path template: {path}")

        params = {}
        for k, v in (query or {}).items():
            if v is None:
                continue
            if isinstance(v, bool):
                v = "true" if v else "false"
            params[k] = v

        kwargs: dict[str, Any] = {"params": params}
        if body is not None and op.method != "get":
            kwargs["json"] = body

        caller = caller_credentials.get()
        if caller is not None and caller.token:
            headers = {"Authorization": f"Bearer {caller.token}"}
            if caller.on_behalf:
                headers["On-Behalf"] = caller.on_behalf
            return await self._http.request(op.method.upper(), path, headers=headers, **kwargs)
        if self.require_caller_token:
            raise PFError(
                "This server needs your own PacketFabric API key. Send it as "
                "'Authorization: Bearer <api key>' (create one in the portal under Settings > API Keys)."
            )

        token = await self._ensure_token()
        r = await self._http.request(op.method.upper(), path, headers=self._headers(token), **kwargs)
        if r.status_code == 401 and not self._static_token:
            token = await self._ensure_token(force=True)
            r = await self._http.request(op.method.upper(), path, headers=self._headers(token), **kwargs)
        return r

    async def delete_api_key(self, token: str, key_uuid: str) -> None:
        # Authenticates only as the key's owner: never the operator's credentials or On-Behalf.
        r = await self._http.delete(
            f"/v2/api-keys/{quote(key_uuid, safe='')}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code >= 400:
            raise PFError(f"Deleting the API key failed ({r.status_code})")

    async def aclose(self) -> None:
        await self._http.aclose()
