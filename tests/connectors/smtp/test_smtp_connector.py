"""Offline SMTP connector tests: no sockets, the client is a recording fake."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from icuhub.connectors.smtp import Smtp
from icuhub.connectors.smtp.models import SendNotificationArgs
from icuhub.kit.errors import PermissionDenied
from icuhub.kit.testing import RouteTransport, make_connector


class FakeClient:
    def __init__(self, refused: dict[str, Any] | None = None, fail: bool = False) -> None:
        self.sent: list[tuple[Any, list[str]]] = []
        self.refused = refused or {}
        self.fail = fail
        self.noops = 0

    async def send(self, message: Any, recipients: list[str]) -> dict[str, Any]:
        self.sent.append((message, recipients))
        return {"message_id": message["Message-ID"], "refused": self.refused}

    async def noop(self) -> None:
        self.noops += 1
        if self.fail:
            raise OSError("connection refused")


def _connector(**config: Any) -> Smtp:
    base = {
        "host": "smtp.example.test",
        "port": 587,
        "from_address": "icuhub@example.test",
        "allowed_recipients": ("*@example.test",),
    }
    connector = make_connector(Smtp, {**base, **config}, RouteTransport({}), {})
    fake = FakeClient()
    connector._client = fake
    return connector  # type: ignore[return-value]


def _args(**extra: Any) -> SendNotificationArgs:
    base: dict[str, Any] = {
        "recipients": ["secops@example.test"],
        "subject": "Approval required",
        "body": "please review",
    }
    return SendNotificationArgs(**{**base, **extra})


def test_plan_is_side_effect_free_and_binds_content() -> None:
    connector = _connector()
    plan = asyncio.run(connector.plan_send(_args()))
    assert plan.changed is True
    assert plan.diff["body_sha256"]
    assert connector._client.sent == [] and connector._client.noops == 0
    other = asyncio.run(connector.plan_send(_args(subject="different")))
    assert other.plan_hash != plan.plan_hash


def test_allowlist_rejects_before_any_network() -> None:
    connector = _connector()
    with pytest.raises(PermissionDenied):
        asyncio.run(connector.plan_send(_args(recipients=["attacker@evil.test"])))
    assert connector._client.sent == []
    open_connector = _connector(allowed_recipients=())
    plan = asyncio.run(open_connector.plan_send(_args(recipients=["anyone@else.test"])))
    assert plan.changed


def test_apply_sends_message_and_returns_message_id() -> None:
    connector = _connector()
    plan = asyncio.run(connector.plan_send(_args()))
    outcome = asyncio.run(connector.apply_send(plan))
    assert outcome.status == "succeeded"
    assert outcome.vendor_ref
    message, recipients = connector._client.sent[0]
    assert recipients == ["secops@example.test"]
    assert message["From"] == "icuhub@example.test"
    assert message["Subject"] == "Approval required"
    assert "please review" in message.get_content()


def test_all_recipients_refused_is_failed() -> None:
    connector = _connector()
    connector._client.refused = {"secops@example.test": (550, b"no")}
    plan = asyncio.run(connector.plan_send(_args()))
    outcome = asyncio.run(connector.apply_send(plan))
    assert outcome.status == "failed"


def test_health_uses_noop_not_send() -> None:
    connector = _connector()
    report = asyncio.run(connector.check())
    assert report.status == "healthy"
    connector._client.fail = True
    degraded = asyncio.run(connector.check())
    assert degraded.status == "degraded"
    assert connector._client.sent == []


def test_declarations() -> None:
    assert Smtp.uses_http is False
    assert set(Smtp.actions()) == {"send_notification"}
    assert Smtp.capabilities == ("Notifier",)
    assert not Smtp.streams()
