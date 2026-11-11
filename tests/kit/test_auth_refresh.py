"""OAuth2RefreshToken: token POSTs through RouteTransport, bound TLS/proxy/timeout, rotation, single-flight, errors."""

import asyncio
import json
import ssl
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from icuhub.kit import OAuth2RefreshToken as ExportedRefreshToken
from icuhub.kit.auth import (
    AUTH_STRATEGIES,
    GitHubAppAuth,
    OAuth2ClientCredentials,
    OAuth2RefreshToken,
    TokenHttp,
    bind_token_transport,
)
from icuhub.kit.errors import AuthFailed, ConfigError, RefreshTokenNotPersisted
from icuhub.kit.http import build_http
from icuhub.kit.testing import RouteTransport
from icuhub.kit.types import ConnectorConfig

API = "https://api.example.test"
TOKEN_URL = "https://auth.example.test/oauth/token"
CLIENT_SECRET = "client-secret-value"


def _auth(refresh_token: str = "rt-1") -> OAuth2RefreshToken:
    return OAuth2RefreshToken(
        token_url=TOKEN_URL,
        client_id="client-id",
        client_secret=CLIENT_SECRET,
        refresh_token=refresh_token,
    )


def _tls(transport: httpx2.AsyncBaseTransport) -> TokenHttp:
    return TokenHttp(verify=ssl.create_default_context(), proxy=None, timeout_s=30.0, transport=transport)


def _token_route(posts: list[dict[str, Any]], responses: list[dict[str, Any]]) -> Callable[[httpx2.Request], dict]:
    """Record each token POST body and answer with the next response spec (the last one repeats)."""

    def handler(request: httpx2.Request) -> dict:
        posts.append(json.loads(request.content))
        return responses[min(len(posts), len(responses)) - 1]

    return handler


def _ok(access_token: str, rotated: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"access_token": access_token, "expires_in": 3600}
    if rotated is not None:
        body["refresh_token"] = rotated
    return {"status": 200, "json": body}


def test_token_post_goes_through_route_transport_and_sets_bearer() -> None:
    posts: list[dict[str, Any]] = []
    api_auth: list[str] = []

    def api(request: httpx2.Request) -> dict:
        api_auth.append(request.headers["Authorization"])
        return {"status": 200, "json": {}}

    transport = RouteTransport(
        {
            ("POST", "/oauth/token"): _token_route(posts, [_ok("at-1", rotated="rt-2")]),
            ("GET", "/rest/api/3/myself"): api,
        }
    )
    http = build_http(ConnectorConfig(base_url=API), _auth(), transport=transport)

    async def go() -> None:
        try:
            await http.request("GET", "/rest/api/3/myself", expected=(200,))
        finally:
            await http.aclose()

    asyncio.run(go())

    assert posts == [
        {
            "grant_type": "refresh_token",
            "client_id": "client-id",
            "client_secret": CLIENT_SECRET,
            "refresh_token": "rt-1",
        }
    ]
    assert api_auth == ["Bearer at-1"]


def test_build_http_binds_tls_proxy_and_timeout_to_token_fetch() -> None:
    auth = _auth()
    transport = RouteTransport({})

    build_http(
        ConnectorConfig(base_url=API, proxy_url="http://proxy.example.test:3128", timeout_s=7.5),
        auth,
        transport=transport,
    )

    bound = auth._bound
    assert isinstance(bound, TokenHttp)
    assert isinstance(bound.verify, ssl.SSLContext)
    assert bound.proxy == "http://proxy.example.test:3128"
    assert bound.timeout_s == 7.5
    assert bound.transport is transport


def test_rebinding_refresh_token_strategy_is_refused() -> None:
    auth = _auth()
    bind_token_transport(auth, _tls(RouteTransport({})))
    with pytest.raises(ConfigError):
        bind_token_transport(auth, _tls(RouteTransport({})))


def test_rebinding_client_credentials_strategy_is_still_refused() -> None:
    auth = OAuth2ClientCredentials(token_url=TOKEN_URL, client_id="client-id", client_secret=CLIENT_SECRET, scope="")
    bind_token_transport(auth, _tls(RouteTransport({})))
    with pytest.raises(ConfigError):
        bind_token_transport(auth, _tls(RouteTransport({})))


def test_unbound_refresh_fails_closed() -> None:
    async def go() -> None:
        await _auth().apply({}, "GET", f"{API}/rest/api/3/myself")

    with pytest.raises(ConfigError):
        asyncio.run(go())


def test_rotated_refresh_token_is_used_for_next_fetch() -> None:
    posts: list[dict[str, Any]] = []
    transport = RouteTransport(
        {
            ("POST", "/oauth/token"): _token_route(
                posts,
                [_ok("at-1", rotated="rt-2"), _ok("at-2")],
            ),
        }
    )
    auth = _auth()
    bind_token_transport(auth, _tls(transport))

    async def go() -> tuple[dict[str, str], dict[str, str]]:
        first: dict[str, str] = {}
        await auth.apply(first, "GET", f"{API}/x")
        await auth.refresh()
        second: dict[str, str] = {}
        await auth.apply(second, "GET", f"{API}/x")
        return first, second

    first, second = asyncio.run(go())

    assert first == {"Authorization": "Bearer at-1"}
    assert second == {"Authorization": "Bearer at-2"}
    assert [post["refresh_token"] for post in posts] == ["rt-1", "rt-2"]


def test_rotation_persistence_failure_never_falls_back_to_memory() -> None:
    auth = _auth()

    async def fail_persistence(_rotated: str) -> None:
        raise OSError("credential store unavailable")

    auth.on_rotate = fail_persistence
    bind_token_transport(auth, _tls(RouteTransport({("POST", "/oauth/token"): _ok("at-1", rotated="rt-2")})))
    headers: dict[str, str] = {}

    with pytest.raises(RefreshTokenNotPersisted):
        asyncio.run(auth.apply(headers, "GET", f"{API}/x"))

    assert headers == {}
    assert auth.refresh_token == "rt-1"
    assert auth._token is None


def test_concurrent_apply_shares_one_token_fetch() -> None:
    posts: list[dict[str, Any]] = []

    async def slow_token(request: httpx2.Request) -> dict:
        posts.append(json.loads(request.content))
        await asyncio.sleep(0.01)
        return _ok("at-1")

    auth = _auth()
    bind_token_transport(auth, _tls(RouteTransport({("POST", "/oauth/token"): slow_token})))

    async def one() -> str:
        headers: dict[str, str] = {}
        await auth.apply(headers, "GET", f"{API}/x")
        return headers["Authorization"]

    async def go() -> list[str]:
        return list(await asyncio.gather(*(one() for _ in range(8))))

    results = asyncio.run(go())

    assert len(posts) == 1
    assert results == ["Bearer at-1"] * 8


def test_token_rejection_reports_status_without_body() -> None:
    transport = RouteTransport(
        {("POST", "/oauth/token"): {"status": 401, "text": "invalid_grant echo-token-body"}},
    )
    auth = _auth()
    bind_token_transport(auth, _tls(transport))

    async def go() -> str:
        with pytest.raises(AuthFailed) as excinfo:
            await auth.apply({}, "GET", f"{API}/x")
        return str(excinfo.value)

    message = asyncio.run(go())

    assert "401" in message
    assert "echo-token-body" not in message
    assert CLIENT_SECRET not in message


def test_repr_hides_secrets() -> None:
    text = repr(_auth())
    assert CLIENT_SECRET not in text
    assert "rt-1" not in text


def test_strategy_is_registered_and_exported() -> None:
    assert AUTH_STRATEGIES["OAuth2RefreshToken"] is OAuth2RefreshToken
    assert ExportedRefreshToken is OAuth2RefreshToken


def test_access_token_is_refetched_inside_60_second_expiry_skew() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    now = [start]
    posts: list[dict[str, Any]] = []
    transport = RouteTransport({("POST", "/oauth/token"): _token_route(posts, [_ok("at-1"), _ok("at-2")])})
    auth = OAuth2RefreshToken(
        token_url=TOKEN_URL,
        client_id="client-id",
        client_secret=CLIENT_SECRET,
        refresh_token="rt-1",
        clock=lambda: now[0],
    )
    bind_token_transport(auth, _tls(transport))

    async def go() -> list[str]:
        seen: list[str] = []
        for offset in (0, 3539, 3541):
            now[0] = start + timedelta(seconds=offset)
            headers: dict[str, str] = {}
            await auth.apply(headers, "GET", f"{API}/x")
            seen.append(headers["Authorization"])
        return seen

    seen = asyncio.run(go())

    assert seen == ["Bearer at-1", "Bearer at-1", "Bearer at-2"]
    assert len(posts) == 2


def test_existing_token_strategies_still_bind_and_refuse_rebinding() -> None:
    key_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    client_credentials = OAuth2ClientCredentials(
        token_url=TOKEN_URL, client_id="client-id", client_secret=CLIENT_SECRET, scope=""
    )
    github = GitHubAppAuth(
        app_id="1",
        private_key_pem=key_pem,
        installation_id="2",
        api_base="https://api.github.example.test",
    )

    for auth in (client_credentials, github):
        settings = _tls(RouteTransport({}))
        bind_token_transport(auth, settings)
        assert auth._bound is settings
        with pytest.raises(ConfigError):
            bind_token_transport(auth, _tls(RouteTransport({})))
