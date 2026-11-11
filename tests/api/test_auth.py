"""Authentication rejection paths. None of these reach the database or the network."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import Iterator
from typing import Any

import pytest
from authlib.jose import JsonWebKey, jwt

import icuhub.api.auth as auth
from icuhub.api.app import create_app
from icuhub.api.problems import AuthenticationError
from icuhub.settings import get_settings

OIDC_ISSUER = "https://idp.example.test"
OIDC_AUDIENCE = "icuhub-api"
OIDC_JWKS = "https://idp.example.test/jwks.json"


def _problem_json(body: bytes) -> dict[str, Any]:
    decoded: dict[str, Any] = json.loads(body)
    return decoded


def _assert_401(status: int, headers: dict[str, str], body: bytes) -> None:
    assert status == 401
    assert headers["content-type"] == "application/problem+json"
    problem = _problem_json(body)
    assert problem["status"] == 401
    assert problem["type"].startswith("https://icuhub/errors/")


def test_missing_authorization_header_is_401(asgi) -> None:
    status, headers, body = asgi(create_app())("GET", "/v1/connections")
    _assert_401(status, headers, body)


@pytest.mark.parametrize("header", ["Bearer", "Bearer   ", "Basic abc", "bearer"])
def test_malformed_bearer_is_401(asgi, header: str) -> None:
    status, headers, body = asgi(create_app())("GET", "/v1/connections", {"Authorization": header})
    _assert_401(status, headers, body)


@pytest.mark.parametrize(
    "token",
    [
        "icuhub_short",  # length <= 16
        "icuhub_abcdefghi" + "x" * 8,  # token[16] is not "_"
    ],
)
def test_malformed_api_key_is_401_without_db(asgi, token: str) -> None:
    status, headers, body = asgi(create_app())("GET", "/v1/connections", {"Authorization": f"Bearer {token}"})
    _assert_401(status, headers, body)
    assert _problem_json(body)["detail"] == "invalid credentials"


def test_non_api_key_bearer_without_oidc_is_401(asgi, monkeypatch: pytest.MonkeyPatch) -> None:
    unconfigured = get_settings().model_copy(
        update={"oidc_issuer": None, "oidc_audience": None, "oidc_jwks_url": None}
    )
    monkeypatch.setattr(auth, "get_settings", lambda: unconfigured)
    status, headers, body = asgi(create_app())(
        "GET", "/v1/connections", {"Authorization": "Bearer nothere_abcdefghi_secret"}
    )
    _assert_401(status, headers, body)


def test_mcp_without_credential_is_401_before_session_manager(asgi) -> None:
    status, headers, body = asgi(create_app())("POST", "/mcp", {"Content-Type": "application/json"}, b"{}")
    _assert_401(status, headers, body)


def test_oidc_not_configured_is_401(asgi, monkeypatch: pytest.MonkeyPatch) -> None:
    unconfigured = get_settings().model_copy(
        update={"oidc_issuer": None, "oidc_audience": None, "oidc_jwks_url": None}
    )
    monkeypatch.setattr(auth, "get_settings", lambda: unconfigured)
    monkeypatch.setattr(auth, "_jwks", _no_network)
    status, headers, body = asgi(create_app())(
        "GET", "/v1/connections", {"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig"}
    )
    _assert_401(status, headers, body)


async def _no_network(url: str) -> dict[str, Any]:
    raise AssertionError(f"unexpected JWKS fetch for {url}")


def _configure_oidc(monkeypatch: pytest.MonkeyPatch, keys: dict[str, Any]) -> None:
    configured = get_settings().model_copy(
        update={"oidc_issuer": OIDC_ISSUER, "oidc_audience": OIDC_AUDIENCE, "oidc_jwks_url": OIDC_JWKS}
    )
    monkeypatch.setattr(auth, "get_settings", lambda: configured)

    async def _fixed(_url: str) -> dict[str, Any]:
        return keys

    monkeypatch.setattr(auth, "_jwks", _fixed)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unsigned_token(claims: dict[str, Any]) -> str:
    header = _b64(json.dumps({"alg": "none"}).encode())
    return f"{header}.{_b64(json.dumps(claims).encode())}."


def _hs256_token(claims: dict[str, Any]) -> str:
    key = JsonWebKey.generate_key("oct", 256, is_private=True)
    token = jwt.encode({"alg": "HS256"}, claims, key)
    return token.decode("ascii") if isinstance(token, bytes) else token


def _rs256_token(claims: dict[str, Any], private: Any) -> str:
    token = jwt.encode({"alg": "RS256"}, claims, private)
    return token.decode("ascii") if isinstance(token, bytes) else token


def _valid_claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": OIDC_ISSUER,
        "aud": OIDC_AUDIENCE,
        "sub": "user-1",
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def oidc_private(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    private = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    keys = {"keys": [private.as_dict(is_private=False)]}
    _configure_oidc(monkeypatch, keys)
    yield private


def test_alg_none_token_is_401(asgi, oidc_private: Any) -> None:
    token = _unsigned_token(_valid_claims())
    status, headers, body = asgi(create_app())("GET", "/v1/connections", {"Authorization": f"Bearer {token}"})
    _assert_401(status, headers, body)


def test_hs256_token_is_401(asgi, oidc_private: Any) -> None:
    token = _hs256_token(_valid_claims())
    status, headers, body = asgi(create_app())("GET", "/v1/connections", {"Authorization": f"Bearer {token}"})
    _assert_401(status, headers, body)


def test_expired_rs256_token_is_401(asgi, oidc_private: Any) -> None:
    token = _rs256_token(_valid_claims(exp=int(time.time()) - 3600), oidc_private)
    status, headers, body = asgi(create_app())("GET", "/v1/connections", {"Authorization": f"Bearer {token}"})
    _assert_401(status, headers, body)


def test_garbage_token_is_401(asgi, oidc_private: Any) -> None:
    status, headers, body = asgi(create_app())(
        "GET", "/v1/connections", {"Authorization": "Bearer not.a.jwt"}
    )
    _assert_401(status, headers, body)


def test_authenticate_raises_generic_error_on_forged_token(oidc_private: Any) -> None:
    token = _hs256_token(_valid_claims())
    with pytest.raises(AuthenticationError) as info:
        asyncio.run(auth.authenticate({"authorization": f"Bearer {token}"}))
    assert info.value.detail == "invalid credentials"
