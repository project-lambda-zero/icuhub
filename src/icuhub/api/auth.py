"""Caller authentication for the ICUHUB API.

Requests carry ``Authorization: Bearer <credential>``. Two credential forms are
accepted and both resolve to a :class:`~icuhub.core.auth_types.Caller`.

Service-account API key
    Format ``icuhub_<prefix>_<secret>`` where ``<prefix>`` is 9 characters
    drawn from the URL-safe alphabet and ``<secret>`` is the remainder. The
    first 16 characters of the full key (``icuhub_<prefix>``) are the stored
    ``key_prefix`` and are used for lookup. ``key_hash`` is the SHA-256 hex
    digest of the full key. The digest is compared with
    :func:`hmac.compare_digest`. Disabled accounts are rejected.

OIDC access token
    A JWT signed with RS256 or ES256 (HS* and ``none`` are never accepted)
    whose issuer equals ``oidc_issuer`` and whose audience includes
    ``oidc_audience``. The signing key comes from the JWKS at ``oidc_jwks_url``
    (cached for five minutes). The ``sub`` claim must map to an enabled
    service-account row for that issuer. Tenant and roles come from that row,
    never from token claims. An ``icuhub_tenant`` claim, if present, must match
    the row's tenant.

Every failure raises :class:`AuthenticationError` with one generic message, so
callers cannot distinguish an unknown key from a disabled one. mTLS identity is
not implemented in this slice.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError
from fastapi import Depends, Request

from icuhub.api.problems import AuthenticationError, AuthorizationError
from icuhub.core.auth_types import Caller
from icuhub.settings import get_settings
from icuhub.storage.system import ServiceAccountRow, service_account_by_prefix, service_account_by_subject

__all__ = [
    "API_KEY_PREFIX",
    "api_key_hash",
    "authenticate",
    "current_caller",
    "require_roles",
]

API_KEY_PREFIX = "icuhub_"
_KEY_PREFIX_LEN = 16  # "icuhub_" + 9 characters
_ALLOWED_ALGORITHMS = ("RS256", "ES256")
_JWKS_TTL_S = 300.0
_JWKS_TIMEOUT_S = 5.0
_GENERIC = "invalid credentials"

_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_jwt = JsonWebToken(list(_ALLOWED_ALGORITHMS))


def api_key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _bearer(headers: Mapping[str, str]) -> str:
    raw = headers.get("authorization", "")
    scheme, _, token = raw.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthenticationError("bearer credential required")
    return token.strip()


async def _authenticate_api_key(token: str) -> Caller:
    if len(token) <= _KEY_PREFIX_LEN or token[_KEY_PREFIX_LEN] != "_" or not token.startswith(API_KEY_PREFIX):
        raise AuthenticationError(_GENERIC)
    row = await service_account_by_prefix(token[:_KEY_PREFIX_LEN])
    if row is None or row.key_hash is None:
        raise AuthenticationError(_GENERIC)
    if not hmac.compare_digest(api_key_hash(token), row.key_hash):
        raise AuthenticationError(_GENERIC)
    return _caller_from_row(row, kind="service_account")


async def _jwks(url: str) -> dict[str, Any]:
    now = time.monotonic()
    cached = _jwks_cache.get(url)
    if cached is not None and now - cached[0] < _JWKS_TTL_S:
        return cached[1]

    def _fetch() -> dict[str, Any]:
        with urllib.request.urlopen(url, timeout=_JWKS_TIMEOUT_S) as response:  # noqa: S310 -- operator-configured HTTPS URL
            data: dict[str, Any] = json.loads(response.read())
        return data

    keys = await asyncio.to_thread(_fetch)
    _jwks_cache[url] = (now, keys)
    return keys


async def _authenticate_oidc(token: str) -> Caller:
    settings = get_settings()
    if settings.oidc_issuer is None or settings.oidc_audience is None or settings.oidc_jwks_url is None:
        raise AuthenticationError("OIDC authentication is not configured")
    key_set = JsonWebKey.import_key_set(await _jwks(settings.oidc_jwks_url))
    try:
        claims = _jwt.decode(
            token,
            key_set,
            claims_options={
                "iss": {"essential": True, "value": settings.oidc_issuer},
                "aud": {"essential": True, "value": settings.oidc_audience},
                "exp": {"essential": True},
                "sub": {"essential": True},
            },
        )
        claims.validate(leeway=60)
    except JoseError as exc:
        raise AuthenticationError(_GENERIC) from exc
    subject = str(claims["sub"])
    row = await service_account_by_subject(settings.oidc_issuer, subject)
    if row is None:
        raise AuthenticationError(_GENERIC)
    tenant_claim = claims.get("icuhub_tenant")
    if tenant_claim is not None and str(tenant_claim) != str(row.tenant_id):
        raise AuthenticationError(_GENERIC)
    return _caller_from_row(row, kind="oidc")


def _caller_from_row(row: ServiceAccountRow, *, kind: str) -> Caller:
    if row.disabled_at is not None:
        raise AuthenticationError(_GENERIC)
    return Caller(
        id=str(row.id),
        tenant_id=row.tenant_id,
        roles=frozenset(row.roles),
        groups=frozenset(row.groups),
        kind=kind,  # type: ignore[arg-type]  # Literal narrowed by the two call sites
    )


async def authenticate(headers: Mapping[str, str]) -> Caller:
    """Resolve the request's bearer credential to a caller or raise AuthenticationError."""
    token = _bearer(headers)
    if token.startswith(API_KEY_PREFIX):
        return await _authenticate_api_key(token)
    return await _authenticate_oidc(token)


async def current_caller(request: Request) -> Caller:
    return await authenticate(request.headers)


def require_roles(*roles: str) -> Callable[..., Any]:
    """FastAPI dependency: the caller must hold at least one of ``roles`` (admin satisfies any)."""

    async def _dependency(caller: Caller = Depends(current_caller)) -> Caller:
        if not any(caller.has_role(role) for role in roles):
            raise AuthorizationError(f"requires one of roles: {', '.join(roles)}")
        return caller

    return _dependency
