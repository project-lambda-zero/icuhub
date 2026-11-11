"""Problem responses, webhook ingress, and health endpoints. No database or network access."""

from __future__ import annotations

import json
from typing import Any

import pytest

import icuhub.api.hooks as hooks
from icuhub.api.app import create_app
from icuhub.api.problems import ProblemError, map_exception, problem_body
from icuhub.core.webhooks import Receipt
from icuhub.kit.errors import WebhookRejected
from icuhub.settings import get_settings


def test_problem_body_shape() -> None:
    body = problem_body(ProblemError(418, "teapot", "I am a teapot", "short and stout"))
    assert body == {
        "type": "https://icuhub/errors/teapot",
        "title": "I am a teapot",
        "status": 418,
        "detail": "short and stout",
    }


def test_webhook_rejected_maps_to_401() -> None:
    mapped = map_exception(WebhookRejected("bad signature"))
    assert mapped.status == 401
    assert mapped.slug == "webhook-rejected"


def test_healthz(asgi) -> None:
    status, headers, body = asgi(create_app())("GET", "/healthz")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_rest_connections_requires_auth(asgi) -> None:
    status, headers, body = asgi(create_app())("GET", "/v1/connections")
    assert status == 401
    assert headers["content-type"] == "application/problem+json"


def test_webhook_receipt_status_is_honored(asgi, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_receive(endpoint_id: str, headers: Any, body: bytes) -> Receipt:
        assert endpoint_id == "ep-1"
        return Receipt(status_code=202, delivery_id="d-1")

    monkeypatch.setattr(hooks, "receive", fake_receive)
    status, _, _ = asgi(create_app())("POST", "/hooks/ep-1", {"content-type": "application/json"}, b"{}")
    assert status == 202


def test_webhook_unknown_endpoint_returns_404(asgi, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_receive(endpoint_id: str, headers: Any, body: bytes) -> Receipt:
        return Receipt(status_code=404, detail="unknown endpoint")

    monkeypatch.setattr(hooks, "receive", fake_receive)
    status, headers, _ = asgi(create_app())("POST", "/hooks/missing", {}, b"{}")
    assert status == 404


def test_webhook_oversized_body_is_413_before_receive(asgi, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_receive(endpoint_id: str, headers: Any, body: bytes) -> Receipt:
        raise AssertionError("receive must not run for an oversized body")

    monkeypatch.setattr(hooks, "receive", fake_receive)
    limit = get_settings().webhook_max_body_bytes
    status, _, _ = asgi(create_app())(
        "POST", "/hooks/ep-1", {"content-length": str(limit + 1)}, b""
    )
    assert status == 413
