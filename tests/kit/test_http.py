"""VendorHttp: status mapping, bounded retries, non-idempotent safety, auth refresh, URL and TLS checks."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any, Literal

import httpx2
import pytest

from icuhub.kit.auth import BearerToken
from icuhub.kit.errors import (
    AuthFailed,
    BudgetExhausted,
    ConfigError,
    Conflict,
    NotFound,
    OutcomeUnknown,
    PermissionDenied,
    RateLimited,
    TransientVendorError,
    UnsafeUrl,
    VendorContractError,
)
from icuhub.kit.http import HttpResult, VendorHttp, build_http
from icuhub.kit.types import ConnectorConfig

BASE = "https://api.example.test"
TOKEN = "s3cr3t-value"

Handler = Callable[[httpx2.Request], httpx2.Response]


def _http(handler: Handler, auth: Any = None, **kwargs: Any) -> VendorHttp:
    return build_http(
        ConnectorConfig(base_url=BASE),
        auth if auth is not None else BearerToken(token=TOKEN),
        transport=httpx2.MockTransport(handler),
        **kwargs,
    )


def _send(
    handler: Handler,
    method: str,
    path: str,
    *,
    auth: Any = None,
    idempotency: Literal["safe_read", "idempotent_write", "non_idempotent"] = "safe_read",
    expected: tuple[int, ...] = (200,),
) -> HttpResult:
    http = _http(handler, auth=auth)

    async def go() -> HttpResult:
        try:
            return await http.request(method, path, idempotency=idempotency, expected=expected)
        finally:
            await http.aclose()

    return asyncio.run(go())


def _status_handler(statuses: list[int], calls: list[httpx2.Request]) -> Handler:
    """Answer each call with the next status in ``statuses``, sending Retry-After: 0 to skip jitter."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        status = statuses[min(len(calls) - 1, len(statuses) - 1)]
        return httpx2.Response(status, headers={"retry-after": "0"}, json={"error": "x"})

    return handler


def _sleep_into(delays: list[float]) -> Callable[[float], Awaitable[None]]:
    """Backoff sleep that records each requested delay instead of waiting."""

    async def sleep(seconds: float) -> None:
        delays.append(seconds)

    return sleep


def _send_with_sleep(
    handler: Handler,
    method: str,
    path: str,
    delays: list[float],
    *,
    idempotency: Literal["safe_read", "idempotent_write", "non_idempotent"] = "safe_read",
) -> HttpResult:
    http = _http(handler, sleep=_sleep_into(delays))

    async def go() -> HttpResult:
        try:
            return await http.request(method, path, idempotency=idempotency, expected=(200,))
        finally:
            await http.aclose()

    return asyncio.run(go())


# --- success and credentials -----------------------------------------------


def test_bearer_token_is_sent_as_authorization_and_returns_parsed_json() -> None:
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers["authorization"])
        return httpx2.Response(200, json={"ok": True})

    result = _send(handler, "GET", "/status")

    assert result.status == 200
    assert result.json() == {"ok": True}
    assert seen == [f"Bearer {TOKEN}"]


def test_bearer_token_is_hidden_from_repr() -> None:
    assert TOKEN not in repr(BearerToken(token=TOKEN))


def test_expected_status_set_admits_a_non_200_success() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(201, json={"created": True})

    result = _send(handler, "POST", "/things", idempotency="idempotent_write", expected=(200, 201))

    assert result.status == 201


# --- status mapping -------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (403, PermissionDenied),
        (404, NotFound),
        (409, Conflict),
        (412, Conflict),
        (401, AuthFailed),
    ],
)
def test_client_error_statuses_map_to_typed_errors(status: int, error_type: type[Exception]) -> None:
    calls: list[httpx2.Request] = []

    with pytest.raises(error_type):
        _send(_status_handler([status], calls), "GET", "/resource")

    assert len(calls) == 1


def test_rate_limit_is_retried_within_budget_then_raises_rate_limited() -> None:
    calls: list[httpx2.Request] = []

    with pytest.raises(RateLimited):
        _send(_status_handler([429], calls), "GET", "/resource")

    assert len(calls) == 4


def test_server_errors_on_a_read_are_retried_then_raise_transient() -> None:
    calls: list[httpx2.Request] = []

    with pytest.raises(TransientVendorError):
        _send(_status_handler([500], calls), "GET", "/resource")

    assert len(calls) == 4


def test_retryable_status_recovers_when_a_later_attempt_succeeds() -> None:
    calls: list[httpx2.Request] = []

    result = _send(_status_handler([503, 503, 200], calls), "GET", "/resource")

    assert result.status == 200
    assert len(calls) == 3


def test_safe_read_transport_error_is_retried_and_recovers_with_bounded_jitter() -> None:
    calls: list[httpx2.Request] = []
    delays: list[float] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        if len(calls) == 1:
            raise httpx2.ConnectError("connection refused")
        return httpx2.Response(200, json={"ok": True})

    result = _send_with_sleep(handler, "GET", "/resource", delays)

    assert result.status == 200
    assert len(calls) == 2
    assert len(delays) == 1
    assert 0.0 <= delays[0] <= 0.5


def test_idempotent_write_503_is_retried_then_succeeds() -> None:
    calls: list[httpx2.Request] = []
    delays: list[float] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx2.Response(503, json={"error": "busy"})
        return httpx2.Response(200, json={"ok": True})

    result = _send_with_sleep(handler, "PUT", "/resource", delays, idempotency="idempotent_write")

    assert result.status == 200
    assert len(calls) == 2
    assert len(delays) == 1
    assert 0.0 <= delays[0] <= 0.5


def test_retry_after_hint_is_used_as_the_backoff_delay() -> None:
    calls: list[httpx2.Request] = []
    delays: list[float] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx2.Response(429, headers={"retry-after": "7"}, json={"error": "slow down"})
        return httpx2.Response(200, json={"ok": True})

    result = _send_with_sleep(handler, "GET", "/resource", delays)

    assert result.status == 200
    assert len(calls) == 2
    assert delays == [7.0]


def test_unexpected_status_is_a_contract_error_and_redirects_are_not_followed() -> None:
    calls: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(302, headers={"location": f"{BASE}/elsewhere"})

    with pytest.raises(VendorContractError, match="unexpected status 302"):
        _send(handler, "GET", "/resource")

    assert len(calls) == 1


def test_unexpected_error_body_is_truncated_in_the_message() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(418, content=b"y" * 2000)

    with pytest.raises(VendorContractError) as info:
        _send(handler, "GET", "/resource")

    message = str(info.value)
    assert "y" * 512 in message
    assert "y" * 513 not in message


def test_authorization_value_echoed_in_an_error_body_is_redacted() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(418, content=f"echo: {request.headers['authorization']}".encode())

    with pytest.raises(VendorContractError) as info:
        _send(handler, "GET", "/resource")

    assert TOKEN not in str(info.value)


# --- non-idempotent safety ------------------------------------------------


def test_non_idempotent_server_error_is_sent_once_and_reports_outcome_unknown() -> None:
    calls: list[httpx2.Request] = []

    with pytest.raises(OutcomeUnknown):
        _send(_status_handler([500], calls), "POST", "/charges", idempotency="non_idempotent")

    assert len(calls) == 1


def test_non_idempotent_transport_failure_reports_outcome_unknown_without_retry_or_backoff() -> None:
    calls: list[httpx2.Request] = []
    delays: list[float] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        raise httpx2.TransportError("connection reset")

    with pytest.raises(OutcomeUnknown):
        _send_with_sleep(handler, "POST", "/charges", delays, idempotency="non_idempotent")

    assert len(calls) == 1
    assert delays == []


# --- auth refresh ---------------------------------------------------------


class _RotatingToken:
    """Credential whose refresh swaps the token once per call, to exercise the 401 path."""

    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._current = 0
        self.refreshes = 0

    async def apply(self, request_headers: dict[str, str], method: str, url: str) -> None:
        request_headers["Authorization"] = f"Bearer {self._tokens[self._current]}"

    async def refresh(self) -> bool:
        self.refreshes += 1
        if self._current + 1 >= len(self._tokens):
            return False
        self._current += 1
        return True


def test_401_refreshes_credentials_once_and_retries_with_the_new_token() -> None:
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers["authorization"])
        if request.headers["authorization"] == "Bearer old":
            return httpx2.Response(401)
        return httpx2.Response(200, json={"ok": True})

    result = _send(handler, "GET", "/resource", auth=_RotatingToken(["old", "new"]))

    assert result.status == 200
    assert seen == ["Bearer old", "Bearer new"]


def test_401_after_refresh_is_retried_only_once_and_raises_auth_failed() -> None:
    calls: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(401)

    with pytest.raises(AuthFailed):
        _send(handler, "GET", "/resource", auth=_RotatingToken(["old", "new"]))

    assert len(calls) == 2


# --- URL safety -----------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example.test/steal",
        "//evil.example.test/steal",
    ],
)
def test_request_to_another_origin_is_rejected_before_any_network_call(target: str) -> None:
    calls: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200)

    with pytest.raises(UnsafeUrl):
        _send(handler, "GET", target)

    assert calls == []


def test_plain_http_base_url_for_a_remote_host_is_a_config_error() -> None:
    with pytest.raises(ConfigError):
        build_http(
            ConnectorConfig(base_url="http://api.example.test"),
            BearerToken(token=TOKEN),
            transport=httpx2.MockTransport(lambda request: httpx2.Response(200)),
        )


# --- bounded download -----------------------------------------------------


def test_stream_download_returns_bytes_under_the_cap() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, content=b"abc")

    http = _http(handler)

    async def go() -> bytes:
        try:
            return await http.stream_download("GET", "/file", max_bytes=10)
        finally:
            await http.aclose()

    assert asyncio.run(go()) == b"abc"


def test_stream_download_over_the_cap_raises_budget_exhausted() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, content=b"x" * 100)

    http = _http(handler)

    async def go() -> bytes:
        try:
            return await http.stream_download("GET", "/file", max_bytes=10)
        finally:
            await http.aclose()

    with pytest.raises(BudgetExhausted):
        asyncio.run(go())


def test_stream_download_sends_caller_headers_on_the_wire() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, content=b"abc")

    http = _http(handler)

    async def go() -> bytes:
        try:
            return await http.stream_download(
                "POST",
                "/file",
                max_bytes=10,
                headers={"X-Http-Method-Override": "GET"},
            )
        finally:
            await http.aclose()

    assert asyncio.run(go()) == b"abc"
    assert seen[0].method == "POST"
    assert seen[0].headers["X-Http-Method-Override"] == "GET"


def test_stream_download_result_sends_json_body() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, content=b"abc")

    http = _http(handler)

    async def go() -> bytes:
        try:
            result = await http.stream_download_result(
                "POST",
                "/file",
                json={"downloadRequests": [{"cveId": "CVE-2026-0001"}]},
                max_bytes=3,
            )
            return result.content
        finally:
            await http.aclose()

    assert asyncio.run(go()) == b"abc"
    assert json.loads(seen[0].content) == {"downloadRequests": [{"cveId": "CVE-2026-0001"}]}


def test_stream_download_without_headers_sends_no_override() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, content=b"abc")

    http = _http(handler)

    async def go() -> bytes:
        try:
            return await http.stream_download("GET", "/file", max_bytes=10)
        finally:
            await http.aclose()

    asyncio.run(go())
    assert "X-Http-Method-Override" not in seen[0].headers


# --- TLS material ---------------------------------------------------------


def test_client_certificate_without_its_key_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="supplied together"):
        build_http(
            ConnectorConfig(base_url=BASE),
            BearerToken(token=TOKEN),
            transport=httpx2.MockTransport(lambda request: httpx2.Response(200)),
            client_cert_pem=b"not-a-real-cert",
        )


def test_authenticate_false_skips_auth_apply_and_401_refresh() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(401, json={"ok": False})

    token = _RotatingToken(["old", "new"])
    http = _http(handler, auth=token)

    async def go() -> HttpResult:
        try:
            return await http.request("POST", "/login", json={"u": "p"}, authenticate=False, expected=(401,))
        finally:
            await http.aclose()

    result = asyncio.run(go())
    assert result.status == 401
    assert token.refreshes == 0
    assert "authorization" not in seen[0].headers
