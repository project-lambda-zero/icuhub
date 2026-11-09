"""Authenticated, retrying, rate-limited HTTP client for vendor APIs.

``import httpx2`` is confined to this module, ``auth.py``, and ``testing.py``.
Redirects are never followed. TLS verification cannot be disabled.
"""

from __future__ import annotations

import asyncio
import os
import random
import re
import ssl
import tempfile
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping
from contextlib import AbstractAsyncContextManager, nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from json import loads as json_loads
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx2
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    retry_if_result,
    stop_after_attempt,
    stop_before_delay,
)

from icuhub.kit._urls import normalize_base_url, resolve_request_url
from icuhub.kit.auth import AuthStrategy, Clock, TokenHttp, bind_token_transport, utc_now
from icuhub.kit.errors import (
    AuthFailed,
    BudgetExhausted,
    ConfigError,
    Conflict,
    ConnectorError,
    NotFound,
    OutcomeUnknown,
    PermissionDenied,
    RateLimited,
    TransientVendorError,
    VendorContractError,
)
from icuhub.kit.types import ConnectorConfig

if TYPE_CHECKING:
    from aiolimiter import AsyncLimiter

__all__ = ["HttpResult", "IdempotencyMode", "VendorHttp", "build_http"]

IdempotencyMode = Literal["safe_read", "idempotent_write", "non_idempotent"]

_RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 4
_TOTAL_BUDGET_S = 120.0
_BASE_BACKOFF_S = 0.5
_MAX_BACKOFF_S = 20.0
_ERROR_BODY_CHARS = 512
_SECRET_MIN_PIECE = 4
_SECRET_SPLIT = re.compile(r"[\s;,=]+")
_DOWNLOAD_CHUNK = 64 * 1024
_REDACTED = "[redacted]"

_Response = tuple[httpx2.Response, tuple[str, ...]]


@dataclass(frozen=True)
class HttpResult:
    """A completed response whose status matched the request's ``expected`` set."""

    status: int
    headers: httpx2.Headers
    url: str
    links: Mapping[str, str]
    encoding: str
    content: bytes = field(repr=False)

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding, errors="replace")

    def json(self) -> Any:
        try:
            return json_loads(self.content)
        except ValueError as exc:
            raise VendorContractError(f"response from {_strip_query(self.url)} is not valid JSON") from exc


@dataclass(frozen=True)
class _Call:
    method: str
    url: str
    params: Mapping[str, Any] | None
    json: Any
    content: bytes | None
    headers: Mapping[str, str]
    pool: str
    authenticate: bool = True


def _strip_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _describe(method: str, url: str) -> str:
    return f"{method.upper()} {_strip_query(url)}"


def _retry_after_seconds(value: str | None, now: datetime) -> float | None:
    """Parse a Retry-After header (delta seconds or HTTP date) into a non-negative delay."""
    if value is None:
        return None
    text = value.strip()
    if text.isdigit():
        return float(text)
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - now).total_seconds())


def _idempotency_key(headers: Mapping[str, str]) -> str | None:
    for name, value in headers.items():
        if name.lower() == "idempotency-key":
            return value
    return None


def _scrub(text: str, secrets: Iterable[str]) -> str:
    """Replace each secret value and its long pieces with a redaction marker."""
    for secret in secrets:
        if not secret:
            continue
        pieces = {secret} | {piece for piece in _SECRET_SPLIT.split(secret) if len(piece) >= _SECRET_MIN_PIECE}
        for piece in sorted(pieces, key=len, reverse=True):
            text = text.replace(piece, _REDACTED)
    return text


def _jitter_delay(attempt_number: int) -> float:
    """Full-jitter exponential backoff: uniform over ``[0, min(cap, base * 2**(attempt - 1))]``."""
    ceiling = min(_MAX_BACKOFF_S, _BASE_BACKOFF_S * (2 ** max(0, attempt_number - 1)))
    return random.uniform(0.0, ceiling)


def _is_retryable(result: _Response) -> bool:
    response, _ = result
    return response.status_code in _RETRYABLE_STATUSES


def _final_outcome(retry_state: RetryCallState) -> Any:
    """Return the last response when the budget ends on a retryable status; re-raise the last transport error."""
    return retry_state.outcome.result()


def _to_result(response: httpx2.Response) -> HttpResult:
    url = str(response.url)
    links = {
        rel: urljoin(url, info["url"])
        for rel, info in response.links.items()
        if rel is not None and "url" in info
    }
    return HttpResult(
        status=response.status_code,
        headers=response.headers,
        url=url,
        links=links,
        encoding=response.encoding or "utf-8",
        content=response.content,
    )


class VendorHttp:
    """Authenticated vendor HTTP client. Construct with ``build_http``.

    Retries apply to ``safe_read`` and ``idempotent_write`` requests only. A
    ``non_idempotent`` request is sent once. When ``limiters`` is supplied, every
    request must name a pool in it (``ConfigError`` otherwise). When it is None,
    requests are unthrottled.
    """

    def __init__(
        self,
        *,
        client: httpx2.AsyncClient,
        auth: AuthStrategy,
        base_url: str,
        extra_hosts: frozenset[str],
        allow_plain_http_loopback: bool,
        limiters: Mapping[str, AsyncLimiter] | None,
        clock: Clock,
        quota_hook: Callable[[httpx2.Headers], None] | None,
        sleep: Callable[[float], Awaitable[None]],
    ) -> None:
        self._client = client
        self._auth = auth
        self._base_url = base_url
        self._extra_hosts = extra_hosts
        self._allow_plain_http_loopback = allow_plain_http_loopback
        self._limiters = None if limiters is None else dict(limiters)
        self._clock = clock
        self._quota_hook = quota_hook
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        idempotency: IdempotencyMode = "safe_read",
        expected: Collection[int] = (200,),
        pool: str = "default",
        authenticate: bool = True,
    ) -> HttpResult:
        """Send one logical request and return its result when the status is in ``expected``.

        ``authenticate=False`` skips the auth strategy and the 401 refresh. Use it only
        for the strategy's own login call (SessionLogin holds its lock while logging in).
        """
        call = _Call(
            method=method,
            url=self._resolve(path_or_url),
            params=params,
            json=json,
            content=content,
            headers=dict(headers or {}),
            pool=pool,
            authenticate=authenticate,
        )
        response, secrets = await self._execute(call, idempotency)
        if authenticate and response.status_code == 401 and await self._auth.refresh():
            await response.aclose()
            response, secrets = await self._execute(call, idempotency)
        if response.status_code in expected:
            return _to_result(response)
        raise self._status_error(response, secrets, call, idempotency)

    async def stream_download(self, method: str, url: str, *, max_bytes: int) -> bytes:
        """Download a response body capped at ``max_bytes``. This path is not retried."""
        call = _Call(
            method=method,
            url=self._resolve(url),
            params=None,
            json=None,
            content=None,
            headers={},
            pool="default",
        )
        try:
            response, secrets = await self._send_once(call, stream=True)
            if response.status_code == 401 and await self._auth.refresh():
                await response.aclose()
                response, secrets = await self._send_once(call, stream=True)
            try:
                return await self._read_capped(response, secrets, call, max_bytes)
            finally:
                await response.aclose()
        except httpx2.TransportError as exc:
            raise TransientVendorError(f"{_describe(call.method, call.url)} failed at the transport layer") from exc

    def _resolve(self, path_or_url: str) -> str:
        return resolve_request_url(
            self._base_url,
            path_or_url,
            extra_hosts=self._extra_hosts,
            allow_plain_http_loopback=self._allow_plain_http_loopback,
        )

    async def _execute(self, call: _Call, idempotency: IdempotencyMode) -> _Response:
        try:
            if idempotency == "non_idempotent":
                return await self._send_once(call, stream=False)
            return await self._send_with_retries(call)
        except httpx2.TransportError as exc:
            if idempotency == "non_idempotent":
                raise OutcomeUnknown(idempotency_key=_idempotency_key(call.headers)) from exc
            raise TransientVendorError(f"{_describe(call.method, call.url)} failed at the transport layer") from exc

    async def _send_with_retries(self, call: _Call) -> _Response:
        retrying = AsyncRetrying(
            stop=stop_after_attempt(_MAX_ATTEMPTS) | stop_before_delay(_TOTAL_BUDGET_S),
            wait=self._backoff,
            retry=retry_if_exception_type(httpx2.TransportError) | retry_if_result(_is_retryable),
            retry_error_callback=_final_outcome,
            sleep=self._sleep,
        )
        return await retrying(self._send_once, call, stream=False)

    def _backoff(self, retry_state: RetryCallState) -> float:
        outcome = retry_state.outcome
        if outcome is not None and not outcome.failed:
            response, _ = outcome.result()
            hinted = _retry_after_seconds(response.headers.get("retry-after"), self._clock())
            if hinted is not None:
                return hinted
        return _jitter_delay(retry_state.attempt_number)

    def _limiter_for(self, pool: str) -> AbstractAsyncContextManager[Any]:
        if self._limiters is None:
            return nullcontext()
        limiter = self._limiters.get(pool)
        if limiter is None:
            raise ConfigError(f"no rate limiter is configured for pool {pool!r}")
        return limiter

    async def _send_once(self, call: _Call, *, stream: bool) -> _Response:
        gate = self._limiter_for(call.pool)
        request_headers = dict(call.headers)
        before = dict(request_headers)
        if call.authenticate:
            await self._auth.apply(request_headers, call.method, call.url)
        secrets = tuple(value for name, value in request_headers.items() if before.get(name) != value)
        request = self._client.build_request(
            call.method,
            call.url,
            params=call.params,
            json=call.json,
            content=call.content,
            headers=request_headers,
        )
        async with gate:
            response = await self._client.send(request, stream=stream)
        if self._quota_hook is not None:
            self._quota_hook(response.headers)
        return response, secrets

    async def _read_capped(
        self,
        response: httpx2.Response,
        secrets: tuple[str, ...],
        call: _Call,
        max_bytes: int,
    ) -> bytes:
        if not 200 <= response.status_code < 300:
            await response.aread()
            raise self._status_error(response, secrets, call, "safe_read")
        where = _describe(call.method, call.url)
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > max_bytes:
            raise BudgetExhausted(f"{where} declares {declared} bytes, above the {max_bytes} byte cap")
        buffer = bytearray()
        async for chunk in response.aiter_bytes(_DOWNLOAD_CHUNK):
            buffer.extend(chunk)
            if len(buffer) > max_bytes:
                raise BudgetExhausted(f"{where} exceeded the {max_bytes} byte cap")
        return bytes(buffer)

    def _status_error(
        self,
        response: httpx2.Response,
        secrets: tuple[str, ...],
        call: _Call,
        idempotency: IdempotencyMode,
    ) -> ConnectorError:
        status = response.status_code
        where = _describe(call.method, call.url)
        if status == 401:
            return AuthFailed(f"{where} rejected authentication")
        if status == 403:
            return PermissionDenied(message=f"{where} is forbidden for this identity")
        if status == 404:
            return NotFound(f"{where} was not found")
        if status in (409, 412):
            return Conflict(f"{where} conflicts with current vendor state")
        if status == 429:
            return RateLimited(
                retry_after_s=_retry_after_seconds(response.headers.get("retry-after"), self._clock()),
                message=f"{where} remained rate limited",
            )
        if status >= 500 and idempotency == "non_idempotent":
            return OutcomeUnknown(idempotency_key=_idempotency_key(call.headers))
        if status == 408 or status >= 500:
            return TransientVendorError(f"{where} returned status {status}")
        body = _scrub(response.content.decode(response.encoding or "utf-8", errors="replace"), secrets)
        return VendorContractError(f"{where} returned unexpected status {status}: {body[:_ERROR_BODY_CHARS]}")


def _ssl_context(
    config: ConnectorConfig,
    client_cert_pem: bytes | None,
    client_key_pem: bytes | None,
) -> ssl.SSLContext:
    if config.ca_bundle_pem:
        try:
            context = ssl.create_default_context(cadata=config.ca_bundle_pem)
        except (ssl.SSLError, ValueError) as exc:
            raise ConfigError("ca_bundle_pem is not a valid PEM certificate bundle") from exc
    else:
        context = ssl.create_default_context()
    configured = config.client_cert is not None
    if (config.client_key is not None) != configured:
        raise ConfigError("client_cert and client_key must be configured together")
    if (client_cert_pem is None) != (client_key_pem is None):
        raise ConfigError("client certificate and key must be supplied together")
    if (client_cert_pem is not None) != configured:
        raise ConfigError("client certificate material must match the client_cert and client_key configuration")
    if client_cert_pem is not None and client_key_pem is not None:
        _load_client_chain(context, client_cert_pem, client_key_pem)
    return context


def _load_client_chain(context: ssl.SSLContext, cert_pem: bytes, key_pem: bytes) -> None:
    """Load a client certificate chain.

    The stdlib accepts only file paths, so the PEM pair is written to a private
    temporary file that is removed before this function returns.
    """
    descriptor, path = tempfile.mkstemp(prefix="icuhub-client-", suffix=".pem")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(cert_pem + b"\n" + key_pem)
        context.load_cert_chain(path)
    except (OSError, ValueError):
        raise ConfigError("client certificate or key could not be loaded") from None
    finally:
        os.remove(path)


def build_http(
    config: ConnectorConfig,
    auth: AuthStrategy,
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
    limiter: Mapping[str, AsyncLimiter] | None = None,
    clock: Clock | None = None,
    extra_hosts: Iterable[str] = (),
    client_cert_pem: bytes | None = None,
    client_key_pem: bytes | None = None,
    quota_hook: Callable[[httpx2.Headers], None] | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> VendorHttp:
    """Build the authenticated vendor client for ``config``.

    ``transport`` replaces the network transport (tests), and token requests
    issued by ``auth`` use it too. ``sleep`` performs retry backoff waits (tests
    inject a recorder so no real time passes). ``limiter`` maps pool names to
    rate limiters; when supplied, every request must name a pool in it. When None,
    requests are unthrottled. ``extra_hosts`` lists additional hostnames that absolute URLs may
    target. ``client_cert_pem`` and ``client_key_pem`` carry the client credential
    material resolved from the ``client_cert`` and ``client_key`` references.

    The connector's CA bundle, client certificate, proxy, and timeout are bound
    into ``auth`` so token fetches use the same TLS and proxy settings as vendor
    requests. An auth strategy binds to one connector only.
    """
    base_url = normalize_base_url(config.base_url, allow_plain_http_loopback=config.allow_plain_http_loopback)
    verify = _ssl_context(config, client_cert_pem, client_key_pem)
    bind_token_transport(
        auth,
        TokenHttp(verify=verify, proxy=config.proxy_url, timeout_s=config.timeout_s, transport=transport),
    )
    client = httpx2.AsyncClient(
        verify=verify,
        transport=transport,
        proxy=config.proxy_url,
        timeout=httpx2.Timeout(config.timeout_s),
        follow_redirects=False,
        trust_env=False,
    )
    return VendorHttp(
        client=client,
        auth=auth,
        base_url=base_url,
        extra_hosts=frozenset(host.lower() for host in extra_hosts),
        allow_plain_http_loopback=config.allow_plain_http_loopback,
        limiters=None if limiter is None else dict(limiter),
        clock=clock if clock is not None else utc_now,
        quota_hook=quota_hook,
        sleep=sleep,
    )
