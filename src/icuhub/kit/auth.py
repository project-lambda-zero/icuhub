"""Authentication strategies applied to vendor HTTP requests.

Every strategy exposes ``async apply(request_headers, method, url)`` and
``async refresh() -> bool``. Secret fields are excluded from ``repr``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import KW_ONLY, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from icuhub.kit._urls import require_https
from icuhub.kit.errors import AuthFailed, ConfigError, TransientVendorError, VendorContractError

__all__ = [
    "AUTH_STRATEGIES",
    "AuthStrategy",
    "BasicAuth",
    "BearerToken",
    "Clock",
    "GitHubAppAuth",
    "HeaderToken",
    "OAuth2ClientCredentials",
    "OAuth2RefreshToken",
    "SessionLogin",
    "TokenHttp",
    "bind_token_transport",
    "utc_now",
]

Clock = Callable[[], datetime]

_OAUTH_EXPIRY_SKEW = timedelta(seconds=60)
_GITHUB_EXPIRY_SKEW = timedelta(minutes=5)
_GITHUB_JWT_BACKDATE_S = 60
_GITHUB_JWT_LIFETIME_S = 540


def utc_now() -> datetime:
    """Return the current aware UTC time."""
    return datetime.now(UTC)


class AuthStrategy(Protocol):
    """Adds credentials to an outgoing request and recovers from rejected credentials."""

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        """Write authentication headers into ``request_headers`` in place."""

    async def refresh(self) -> bool:
        """Discard cached credentials and obtain new ones. Return False when nothing can be refreshed."""


@dataclass(frozen=True)
class BearerToken:
    """Static bearer token sent as ``Authorization: Bearer``."""

    token: str = field(repr=False)

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        request_headers["Authorization"] = f"Bearer {self.token}"

    async def refresh(self) -> bool:
        return False


@dataclass(frozen=True)
class BasicAuth:
    """HTTP Basic credentials."""

    user: str
    password: str = field(repr=False)

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        raw = f"{self.user}:{self.password}".encode()
        request_headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")

    async def refresh(self) -> bool:
        return False


@dataclass(frozen=True)
class HeaderToken:
    """A static value sent in an arbitrary header, optionally with a scheme prefix."""

    header: str
    value: str = field(repr=False)
    prefix: str = ""

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        request_headers[self.header] = self.prefix + self.value

    async def refresh(self) -> bool:
        return False


@dataclass(frozen=True)
class TokenHttp:
    """Connector TLS, proxy, and timeout settings that token fetches inherit.

    ``transport`` is the connector's transport override (tests); a strategy's own
    ``transport`` takes precedence over it.
    """

    verify: ssl.SSLContext = field(repr=False)
    proxy: str | None
    timeout_s: float
    transport: httpx2.AsyncBaseTransport | None = field(default=None, repr=False)


async def _token_request(
    bound: TokenHttp | None,
    transport: httpx2.AsyncBaseTransport | None,
    method: str,
    url: str,
    *,
    expected: tuple[int, ...],
    **kwargs: Any,
) -> dict[str, Any]:
    """Call a token endpoint and return its JSON object body.

    Error messages carry the status code only, never the response body.
    """
    if bound is None:
        raise ConfigError("token endpoint requested before the auth strategy was bound to a connector")
    effective = transport if transport is not None else bound.transport
    try:
        async with httpx2.AsyncClient(
            verify=bound.verify,
            transport=effective,
            proxy=bound.proxy,
            timeout=httpx2.Timeout(bound.timeout_s),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.request(method, url, **kwargs)
    except httpx2.TransportError as exc:
        raise TransientVendorError("token endpoint transport failure") from exc
    status = response.status_code
    if status in expected:
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


@dataclass
class OAuth2ClientCredentials:
    """OAuth 2.0 client-credentials grant with client_secret_post.

    The access token is cached until 60 seconds before expiry. Concurrent callers
    share one token fetch.
    """

    token_url: str
    client_id: str
    client_secret: str = field(repr=False)
    scope: str
    _: KW_ONLY
    extra_form: Mapping[str, str] = field(default_factory=dict)
    transport: httpx2.AsyncBaseTransport | None = field(default=None, repr=False)
    clock: Clock = field(default=utc_now, repr=False)
    _bound: TokenHttp | None = field(default=None, init=False, repr=False, compare=False)
    _token: str | None = field(default=None, init=False, repr=False, compare=False)
    _expires_at: datetime | None = field(default=None, init=False, repr=False, compare=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        require_https(self.token_url)

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
            if self.clock() < self._expires_at - _OAUTH_EXPIRY_SKEW:
                return self._token
        return await self._fetch_locked()

    async def _fetch_locked(self) -> str:
        form: dict[str, str] = dict(self.extra_form)
        form["grant_type"] = "client_credentials"
        form["client_id"] = self.client_id
        form["client_secret"] = self.client_secret
        if self.scope:
            form["scope"] = self.scope
        body = await _token_request(
            self._bound,
            self.transport,
            "POST",
            self.token_url,
            expected=(200,),
            data=form,
        )
        token = body.get("access_token")
        expires_in = body.get("expires_in")
        if not isinstance(token, str) or not token:
            raise VendorContractError("token response has no access_token")
        if isinstance(expires_in, bool) or not isinstance(expires_in, int | float) or expires_in <= 0:
            raise VendorContractError("token response has no positive expires_in")
        self._token = token
        self._expires_at = self.clock() + timedelta(seconds=float(expires_in))
        return token


@dataclass
class OAuth2RefreshToken:
    """OAuth 2.0 refresh-token grant with rotating refresh tokens.

    The access token is cached until 60 seconds before expiry. Concurrent callers
    share one token fetch. A rotated refresh token returned by the token endpoint
    replaces the held one in memory; kit secrets are read-only, so rotation is not
    persisted across process restarts.
    """

    token_url: str
    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)
    refresh_token: str = field(repr=False)
    _: KW_ONLY
    transport: httpx2.AsyncBaseTransport | None = field(default=None, repr=False)
    clock: Clock = field(default=utc_now, repr=False)
    _bound: TokenHttp | None = field(default=None, init=False, repr=False, compare=False)
    _token: str | None = field(default=None, init=False, repr=False, compare=False)
    _expires_at: datetime | None = field(default=None, init=False, repr=False, compare=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        require_https(self.token_url)
        if not self.client_id or not self.client_secret or not self.refresh_token:
            raise ConfigError("OAuth refresh-token grant requires client_id, client_secret, and refresh_token")

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
            if self.clock() < self._expires_at - _OAUTH_EXPIRY_SKEW:
                return self._token
        return await self._fetch_locked()

    async def _fetch_locked(self) -> str:
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
        }
        body = await _token_request(
            self._bound,
            self.transport,
            "POST",
            self.token_url,
            expected=(200,),
            json=payload,
        )
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


@dataclass
class SessionLogin:
    """Session header obtained from a caller-supplied login callable.

    The callable returns ``(header_name, header_value, expires_at)``. A session
    with ``expires_at=None`` is cached indefinitely. ``refresh`` forces a new login.
    """

    login: Callable[[], Awaitable[tuple[str, str, datetime | None]]] = field(repr=False)
    _: KW_ONLY
    clock: Clock = field(default=utc_now, repr=False)
    _session: tuple[str, str] | None = field(default=None, init=False, repr=False, compare=False)
    _expires_at: datetime | None = field(default=None, init=False, repr=False, compare=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False, compare=False)

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        async with self._lock:
            name, value = await self._current_locked()
        request_headers[name] = value

    async def refresh(self) -> bool:
        async with self._lock:
            await self._login_locked()
        return True

    async def _current_locked(self) -> tuple[str, str]:
        if self._session is not None and (self._expires_at is None or self.clock() < self._expires_at):
            return self._session
        return await self._login_locked()

    async def _login_locked(self) -> tuple[str, str]:
        name, value, expires_at = await self.login()
        if expires_at is not None and expires_at.utcoffset() is None:
            raise ConfigError("session login expires_at must be timezone-aware")
        if not name or not value:
            raise VendorContractError("session login returned an empty header name or value")
        session = (name, value)
        self._session = session
        self._expires_at = expires_at
        return session


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _compact_json(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass
class GitHubAppAuth:
    """GitHub App installation token.

    An RS256 app JWT is exchanged for an installation access token. The token is
    cached until 5 minutes before expiry.
    """

    app_id: str | int
    private_key_pem: bytes = field(repr=False)
    installation_id: str | int
    api_base: str
    _: KW_ONLY
    transport: httpx2.AsyncBaseTransport | None = field(default=None, repr=False)
    clock: Clock = field(default=utc_now, repr=False)
    _key: RSAPrivateKey = field(init=False, repr=False, compare=False)
    _bound: TokenHttp | None = field(default=None, init=False, repr=False, compare=False)
    _token: str | None = field(default=None, init=False, repr=False, compare=False)
    _expires_at: datetime | None = field(default=None, init=False, repr=False, compare=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.api_base = require_https(self.api_base).rstrip("/")
        if not str(self.installation_id).isdigit():
            raise ConfigError("GitHub installation_id must be numeric")
        try:
            key = serialization.load_pem_private_key(self.private_key_pem, password=None)
        except (ValueError, TypeError):
            raise ConfigError("GitHub App private key is not an unencrypted PEM private key") from None
        if not isinstance(key, RSAPrivateKey):
            raise ConfigError("GitHub App private key must be RSA")
        self._key = key

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
            if self.clock() < self._expires_at - _GITHUB_EXPIRY_SKEW:
                return self._token
        return await self._fetch_locked()

    def _app_jwt(self) -> str:
        now = int(self.clock().timestamp())
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iat": now - _GITHUB_JWT_BACKDATE_S,
            "exp": now + _GITHUB_JWT_LIFETIME_S,
            "iss": str(self.app_id),
        }
        signing_input = f"{_b64url(_compact_json(header))}.{_b64url(_compact_json(payload))}"
        signature = self._key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{_b64url(signature)}"

    async def _fetch_locked(self) -> str:
        body = await _token_request(
            self._bound,
            self.transport,
            "POST",
            f"{self.api_base}/app/installations/{self.installation_id}/access_tokens",
            expected=(200, 201),
            headers={
                "Authorization": f"Bearer {self._app_jwt()}",
                "Accept": "application/vnd.github+json",
            },
        )
        token = body.get("token")
        expires_raw = body.get("expires_at")
        if not isinstance(token, str) or not token:
            raise VendorContractError("installation token response has no token")
        if not isinstance(expires_raw, str):
            raise VendorContractError("installation token response has no expires_at")
        try:
            expires_at = datetime.fromisoformat(expires_raw)
        except ValueError as exc:
            raise VendorContractError("installation token expires_at is not ISO 8601") from exc
        if expires_at.utcoffset() is None:
            raise VendorContractError("installation token expires_at is not timezone-aware")
        self._token = token
        self._expires_at = expires_at
        return token


def bind_token_transport(auth: AuthStrategy, settings: TokenHttp) -> None:
    """Attach a connector's TLS, proxy, and timeout settings to a strategy that fetches tokens.

    Strategies that perform no token HTTP are left unchanged. A strategy binds
    once: rebinding raises ``ConfigError`` so one instance cannot silently serve
    two connectors with different trust settings.
    """
    if not isinstance(auth, OAuth2ClientCredentials | OAuth2RefreshToken | GitHubAppAuth):
        return
    if auth._bound is not None:
        raise ConfigError("auth strategy is already bound to a connector; create one strategy per connector")
    auth._bound = settings


AUTH_STRATEGIES: dict[str, type] = {
    "BearerToken": BearerToken,
    "BasicAuth": BasicAuth,
    "HeaderToken": HeaderToken,
    "OAuth2ClientCredentials": OAuth2ClientCredentials,
    "OAuth2RefreshToken": OAuth2RefreshToken,
    "SessionLogin": SessionLogin,
    "GitHubAppAuth": GitHubAppAuth,
}
