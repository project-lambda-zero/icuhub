"""OAuth 2.0 (3LO) refresh-token authentication for Jira Cloud.

Kit's ``OAuth2ClientCredentials`` hardcodes the client-credentials grant, so the refresh-token
grant lives here. The strategy keeps the same contract as kit's token strategies: tokens are
cached until 60 seconds before expiry, concurrent callers share one fetch, and token-endpoint
errors carry the status code only, never the response body.

Atlassian rotates refresh tokens. A rotated token is held in memory for the life of this
strategy. Kit secrets are read-only, so the rotated token is not persisted; see the gap
register entry for Jira Cloud 3LO token persistence.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import httpx2

from icuhub.kit.auth import Clock, utc_now
from icuhub.kit.errors import AuthFailed, ConfigError, TransientVendorError, VendorContractError

__all__ = ["ATLASSIAN_TOKEN_URL", "OAuth2RefreshToken"]

ATLASSIAN_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
_EXPIRY_SKEW = timedelta(seconds=60)
_TIMEOUT_S = 30.0


@dataclass
class OAuth2RefreshToken:
    """Atlassian 3LO refresh-token grant. One instance serves one connector."""

    client_id: str
    client_secret: str = field(repr=False)
    refresh_token: str = field(repr=False)
    transport: httpx2.AsyncBaseTransport | None = field(default=None, repr=False)
    clock: Clock = field(default=utc_now, repr=False)
    _token: str | None = field(default=None, init=False, repr=False, compare=False)
    _expires_at: datetime | None = field(default=None, init=False, repr=False, compare=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_secret or not self.refresh_token:
            raise ConfigError("OAuth 3LO requires client_id, client_secret, and refresh_token")

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        async with self._lock:
            token = await self._current_token_locked()
        request_headers["Authorization"] = f"Bearer {token}"

    async def refresh(self) -> bool:
        async with self._lock:
            await self._fetch_locked()
        return True

    async def _current_token_locked(self) -> str:
        if self._token is not None and self._expires_at is not None:
            if self.clock() < self._expires_at - _EXPIRY_SKEW:
                return self._token
        return await self._fetch_locked()

    async def _fetch_locked(self) -> str:
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
        }
        body = await _post_token(self.transport, payload)
        token = body.get("access_token")
        expires_in = body.get("expires_in")
        if not isinstance(token, str) or not token:
            raise VendorContractError("token response has no access_token")
        if isinstance(expires_in, bool) or not isinstance(expires_in, int | float) or expires_in <= 0:
            raise VendorContractError("token response has no positive expires_in")
        rotated = body.get("refresh_token")
        if isinstance(rotated, str) and rotated:
            self.refresh_token = rotated
        self._token = token
        self._expires_at = self.clock() + timedelta(seconds=float(expires_in))
        return token


async def _post_token(transport: httpx2.AsyncBaseTransport | None, payload: dict[str, str]) -> dict[str, Any]:
    """POST the refresh grant and return the JSON object body.

    Plain HTTPS to the Atlassian token endpoint with default TLS verification, no environment
    proxy, and no redirects. Error messages carry the status code only.
    """
    try:
        async with httpx2.AsyncClient(
            transport=transport,
            timeout=httpx2.Timeout(_TIMEOUT_S),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(ATLASSIAN_TOKEN_URL, json=payload)
    except httpx2.TransportError as exc:
        raise TransientVendorError("token endpoint transport failure") from exc
    status = response.status_code
    if status == 200:
        try:
            body = response.json()
        except ValueError as exc:
            raise VendorContractError("token endpoint returned a non-JSON body") from exc
        if not isinstance(body, dict):
            raise VendorContractError("token endpoint returned a non-object JSON body")
        return body
    if status in (400, 401, 403):
        raise AuthFailed(f"token endpoint rejected credentials with status {status}")
    if status == 429 or status >= 500:
        raise TransientVendorError(f"token endpoint returned status {status}")
    raise VendorContractError(f"token endpoint returned unexpected status {status}")
