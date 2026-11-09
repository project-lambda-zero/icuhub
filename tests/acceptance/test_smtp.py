"""Live SMTP acceptance (operator-run): real connect/NOOP and an opt-in send."""

from __future__ import annotations

import asyncio

from icuhub.connectors.smtp import Smtp
from icuhub.connectors.smtp.models import SendNotificationArgs
from icuhub.kit.testing import RouteTransport, make_connector

ACCEPTANCE_KIND = "smtp"


def _connector(acceptance) -> Smtp:
    return make_connector(Smtp, acceptance.config, RouteTransport({}), acceptance.secrets)  # type: ignore[return-value]


def test_health(acceptance) -> None:
    connector = _connector(acceptance)
    report = asyncio.run(connector.check())
    acceptance.record("health_noop", report.status == "healthy", report.status)
    assert report.status == "healthy"


def test_send_notification(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    recipient = acceptance.params["recipient"]
    args = SendNotificationArgs(recipients=[recipient], subject="ICUHUB acceptance", body="acceptance send")
    plan = asyncio.run(connector.plan_send(args))
    outcome = asyncio.run(connector.apply_send(plan))
    acceptance.record("send_notification", outcome.status == "succeeded", outcome.status)
    assert outcome.status == "succeeded"
