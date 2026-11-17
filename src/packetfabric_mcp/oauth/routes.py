from __future__ import annotations

import json
from typing import Any

from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import JWT_BEARER_GRANT_TYPE, OAuthClientMetadata
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .config import OAuthConfig, origin_allowed
from .provider import InvalidRequest, PacketFabricOAuthProvider

MAX_CALLBACK_BODY_BYTES = 16 * 1024
_NO_STORE = {"Cache-Control": "no-store"}
_INVALID_REQUEST = {"error": "invalid_request"}


class _BodyTooLarge(Exception):
    pass


def _json(content: dict[str, Any], status: int = 200, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(content, status_code=status, headers={**_NO_STORE, **(headers or {})})


def _invalid_metadata(description: str) -> JSONResponse:
    return _json({"error": "invalid_client_metadata", "error_description": description}, 400, _REGISTER_CORS)


# Same open CORS policy as the SDK's registration endpoint: registration carries no credentials.
_REGISTER_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


async def _read_capped(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise _BodyTooLarge
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise _BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def oauth_routes(provider: PacketFabricOAuthProvider, config: OAuthConfig) -> list[Route]:
    def cors(request: Request) -> dict[str, str]:
        origin = request.headers.get("origin")
        if not origin_allowed(origin, config.portal_origins):
            return {}
        return {
            "Access-Control-Allow-Origin": origin,
            "Vary": "Origin",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }

    async def preflight(request: Request) -> Response:
        return Response(status_code=204, headers={**_NO_STORE, **cors(request)})

    async def register_preflight(request: Request) -> Response:
        return Response(status_code=204, headers={**_NO_STORE, **_REGISTER_CORS})

    async def register(request: Request) -> Response:
        # Mirrors the SDK's registration handler checks; only credential minting and the
        # redirect allowlist differ, and both belong to the provider.
        try:
            metadata = OAuthClientMetadata.model_validate_json(await request.body())
        except ValidationError as e:
            return _invalid_metadata("; ".join(f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors()))
        if metadata.token_endpoint_auth_method == "private_key_jwt":
            return _invalid_metadata("token_endpoint_auth_method 'private_key_jwt' is not supported")
        if "authorization_code" not in metadata.grant_types:
            return _invalid_metadata("grant_types must include 'authorization_code'")
        if JWT_BEARER_GRANT_TYPE in metadata.grant_types:
            return _invalid_metadata(
                f"grant_types must not include '{JWT_BEARER_GRANT_TYPE}'; "
                "the identity-assertion grant requires a pre-registered client"
            )
        if "code" not in metadata.response_types:
            return _invalid_metadata("response_types must include 'code' for authorization_code grant")
        try:
            client_info = await provider.create_client(metadata)
        except RegistrationError as e:
            return _json({"error": e.error, "error_description": e.error_description}, 400, _REGISTER_CORS)
        info = client_info.model_dump(mode="json", exclude_none=True)
        if client_info.client_secret and client_info.client_secret_expires_at is None:
            info["client_secret_expires_at"] = 0  # RFC 7591: required with a secret; 0 means it never expires
        return _json(info, 201, _REGISTER_CORS)

    async def describe(request: Request) -> Response:
        headers = cors(request)
        token = request.query_params.get("request")
        if not token:
            return _json(_INVALID_REQUEST, 400, headers)
        try:
            return _json(await provider.describe_request(token), 200, headers)
        except InvalidRequest:
            return _json(_INVALID_REQUEST, 400, headers)

    async def callback(request: Request) -> Response:
        if not origin_allowed(request.headers.get("origin"), config.portal_origins):
            return _json({"error": "forbidden_origin"}, 403)
        headers = cors(request)
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return _json(_INVALID_REQUEST, 400, headers)
        try:
            raw = await _read_capped(request, MAX_CALLBACK_BODY_BYTES)
        except _BodyTooLarge:
            return _json({"error": "request_too_large"}, 413, headers)
        try:
            body = json.loads(raw)
        except ValueError:
            return _json(_INVALID_REQUEST, 400, headers)
        parsed = _parse_callback(body)
        if parsed is None:
            return _json(_INVALID_REQUEST, 400, headers)
        token, api_key, key_uuid = parsed
        try:
            if api_key is None:
                redirect_to = await provider.deny_request(token)
            else:
                redirect_to = await provider.complete_request(token, api_key=api_key, key_uuid=key_uuid)
        except InvalidRequest:
            return _json(_INVALID_REQUEST, 400, headers)
        return _json({"redirect_to": redirect_to}, 200, headers)

    return [
        Route("/register", register, methods=["POST"]),
        Route("/register", register_preflight, methods=["OPTIONS"]),
        Route("/oauth/request", describe, methods=["GET"]),
        Route("/oauth/request", preflight, methods=["OPTIONS"]),
        Route("/oauth/callback", callback, methods=["POST"]),
        Route("/oauth/callback", preflight, methods=["OPTIONS"]),
    ]


def _non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _parse_callback(body: Any) -> tuple[str, str | None, str | None] | None:
    if not isinstance(body, dict) or not _non_empty_str(body.get("request")):
        return None
    token = body["request"]
    if "error" in body:
        if body["error"] != "access_denied" or "api_key" in body or "key_uuid" in body:
            return None
        return token, None, None
    if _non_empty_str(body.get("api_key")) and _non_empty_str(body.get("key_uuid")):
        return token, body["api_key"], body["key_uuid"]
    return None
