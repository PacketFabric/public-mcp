"""Thin async HTTP client for the PacketFabric API (auth + request plumbing)."""

from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib.parse import quote

import httpx

from . import __version__
from .spec import Operation


class PFError(Exception):
    pass


class PacketFabricClient:
    def __init__(self, base_url: str):
        self.base_url = os.environ.get("PF_API_URL", base_url).rstrip("/")
        self._token: str | None = os.environ.get("PF_TOKEN") or os.environ.get("PF_API_KEY") or None
        self._login = os.environ.get("PF_LOGIN") or os.environ.get("PF_USER")
        self._password = os.environ.get("PF_PASSWORD")
        self._static_token = self._token is not None
        self._on_behalf = os.environ.get("PF_ON_BEHALF") or None
        self._lock = asyncio.Lock()
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(float(os.environ.get("PF_TIMEOUT", "60"))),
            headers={"User-Agent": f"packetfabric-mcp/{__version__}", "Accept": "application/json"},
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

        token = await self._ensure_token()
        kwargs: dict[str, Any] = {"params": params}
        if body is not None and op.method != "get":
            kwargs["json"] = body
        r = await self._http.request(op.method.upper(), path, headers=self._headers(token), **kwargs)
        if r.status_code == 401 and not self._static_token:
            token = await self._ensure_token(force=True)
            r = await self._http.request(op.method.upper(), path, headers=self._headers(token), **kwargs)
        return r

    async def aclose(self) -> None:
        await self._http.aclose()
