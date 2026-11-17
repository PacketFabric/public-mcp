from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyHttpUrl, Field, ValidationError

from ..client import PacketFabricClient, PFError
from .config import OAuthConfig, redirect_allowed, redirect_display
from .seal import Sealer, is_access_token

log = logging.getLogger(__name__)

RAW_KEY_CLIENT_ID = "api-key"
_OUR_PREFIX = "pfmcp_"
REQUEST_TTL_SECONDS = 600
CODE_TTL_SECONDS = 300
# Tokens lapse a minute before the key does, so a client never presents an already-dead key.
KEY_EXPIRY_MARGIN_SECONDS = 60


class PFAuthorizationCode(AuthorizationCode):
    pf_key: str = Field(repr=False)
    key_uuid: str
    key_expires_at: int


class PFAccessToken(AccessToken):
    key_uuid: str | None = None

    # `token` holds the PacketFabric API key itself.
    def __repr_args__(self) -> Any:
        return [(k, v) for k, v in super().__repr_args__() if k != "token"]


class InvalidRequest(Exception):
    pass


def _now() -> int:
    return int(time.time())


def _same_resource(a: str, b: str) -> bool:
    try:
        return str(AnyHttpUrl(a)).removesuffix("/") == str(AnyHttpUrl(b)).removesuffix("/")
    except ValidationError:
        return False


class PacketFabricOAuthProvider:
    def __init__(self, config: OAuthConfig, sealer: Sealer, pf: PacketFabricClient) -> None:
        self.config = config
        self.sealer = sealer
        self.pf = pf

    async def create_client(self, metadata: OAuthClientMetadata) -> OAuthClientInformationFull:
        payload = metadata.model_dump(mode="json", exclude_none=True)
        redirect_uris = payload.get("redirect_uris") or []
        if not redirect_uris or not all(redirect_allowed(str(u), self.config.allowed_redirects) for u in redirect_uris):
            raise RegistrationError(
                error="invalid_redirect_uri", error_description="redirect_uri is not allowed for this server"
            )
        payload.setdefault("token_endpoint_auth_method", "client_secret_post")
        payload["client_id_issued_at"] = _now()
        return self._client_info(self.sealer.seal("client", payload, expires_at=None), payload)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        payload = self.sealer.unseal("client", client_id, now=_now())
        if payload is None:
            return None
        try:
            return self._client_info(client_id, payload)
        except ValueError:
            return None

    def _client_info(self, client_id: str, payload: dict[str, Any]) -> OAuthClientInformationFull:
        secret = None
        if payload.get("token_endpoint_auth_method") != "none":
            secret = self.sealer.client_secret(client_id)
        # Redirects delisted since registration are dropped, so the SDK's authorize handler refuses
        # them with a direct 400 instead of sending its error redirect there.
        allowed = self.config.allowed_redirects
        redirect_uris = [u for u in payload.get("redirect_uris") or [] if redirect_allowed(u, allowed)]
        return OAuthClientInformationFull(
            client_id=client_id, client_secret=secret, **{**payload, "redirect_uris": redirect_uris}
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise NotImplementedError("clients are registered through create_client")

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        redirect_uri = str(params.redirect_uri)
        # Re-checked here so removing an allowlist entry also locks out clients registered before.
        if not redirect_allowed(redirect_uri, self.config.allowed_redirects):
            raise AuthorizeError(error="invalid_request", error_description="redirect_uri is not allowed")
        if params.resource is not None and not _same_resource(params.resource, self.config.resource_url):
            raise AuthorizeError(error="invalid_target", error_description="unknown resource")
        expires_at = _now() + REQUEST_TTL_SECONDS
        token = self.sealer.seal(
            "request",
            {
                "client_id": client.client_id,
                "redirect_uri": redirect_uri,
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "code_challenge": params.code_challenge,
                "state": params.state,
                "resource": self.config.resource_url,
                "scopes": params.scopes,
                "expires_at": expires_at,
            },
            expires_at=expires_at,
        )
        return f"{self.config.portal_url}/mcp/connect?request={quote(token, safe='')}"

    def _pending(self, request: str) -> dict[str, Any]:
        payload = self.sealer.unseal("request", request, now=_now())
        if payload is None:
            raise InvalidRequest("invalid or expired request")
        return payload

    async def describe_request(self, request: str) -> dict[str, Any]:
        pending = self._pending(request)
        client = await self.get_client(pending["client_id"])
        host = redirect_display(pending["redirect_uri"])
        return {
            "client_name": (client.client_name if client else None) or host,
            "redirect_host": host,
            "expires_at": pending["expires_at"],
            "key_ttl_seconds": self.config.key_ttl_seconds,
        }

    async def complete_request(self, request: str, *, api_key: str, key_uuid: str) -> str:
        pending = self._pending(request)
        now = _now()
        expires_at = now + CODE_TTL_SECONDS
        code = self.sealer.seal(
            "code",
            {
                **pending,
                "expires_at": expires_at,
                "pf_key": api_key,
                "key_uuid": key_uuid,
                "key_expires_at": now + self.config.key_ttl_seconds - KEY_EXPIRY_MARGIN_SECONDS,
            },
            expires_at=expires_at,
        )
        return construct_redirect_uri(
            pending["redirect_uri"], code=code, state=pending["state"], iss=self.config.public_url
        )

    async def deny_request(self, request: str) -> str:
        pending = self._pending(request)
        return construct_redirect_uri(
            pending["redirect_uri"], error="access_denied", state=pending["state"], iss=self.config.public_url
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> PFAuthorizationCode | None:
        payload = self.sealer.unseal("code", authorization_code, now=_now())
        if payload is None or payload.get("client_id") != client.client_id:
            return None
        return PFAuthorizationCode(
            code=authorization_code,
            scopes=payload.get("scopes") or [],
            expires_at=payload["expires_at"],
            client_id=payload["client_id"],
            code_challenge=payload["code_challenge"],
            redirect_uri=payload["redirect_uri"],
            redirect_uri_provided_explicitly=payload["redirect_uri_provided_explicitly"],
            resource=payload.get("resource"),
            pf_key=payload["pf_key"],
            key_uuid=payload["key_uuid"],
            key_expires_at=payload["key_expires_at"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: PFAuthorizationCode
    ) -> OAuthToken:
        now = _now()
        if authorization_code.key_expires_at <= now:
            raise TokenError(error="invalid_grant", error_description="authorization code has expired")
        access = self.sealer.seal(
            "access",
            {
                "pf_key": authorization_code.pf_key,
                "key_uuid": authorization_code.key_uuid,
                "client_id": authorization_code.client_id,
                "resource": authorization_code.resource,
                "expires_at": authorization_code.key_expires_at,
            },
            expires_at=authorization_code.key_expires_at,
        )
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=authorization_code.key_expires_at - now)

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        raise TokenError(error="unsupported_grant_type", error_description="refresh tokens are not issued")

    async def load_access_token(self, token: str) -> PFAccessToken | None:
        if not is_access_token(token):
            # Anything in our namespace (e.g. a code) must never be forwarded to PacketFabric as if it were a key.
            if token.startswith(_OUR_PREFIX):
                return None
            # Anything else is a PacketFabric API key pasted by the user.
            return PFAccessToken(
                token=token, client_id=RAW_KEY_CLIENT_ID, scopes=[], expires_at=None, resource=self.config.resource_url
            )
        payload = self.sealer.unseal("access", token, now=_now())
        if payload is None:
            return None
        return PFAccessToken(
            token=payload["pf_key"],
            client_id=payload["client_id"],
            scopes=[],
            expires_at=payload["expires_at"],
            resource=payload.get("resource"),
            key_uuid=payload["key_uuid"],
        )

    async def revoke_token(self, token: PFAccessToken | RefreshToken) -> None:
        if not isinstance(token, PFAccessToken) or not token.key_uuid:
            return
        try:
            await self.pf.delete_api_key(token.token, token.key_uuid)
        except (PFError, httpx.HTTPError) as e:
            # The exception text may embed the request URL, so only its type is logged.
            log.warning("Could not delete the API key behind a revoked token (%s)", type(e).__name__)
