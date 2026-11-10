"""Plan, apply, and reconcile tests for Prisma Cloud writes."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from icuhub.connectors.prisma_cloud import PrismaCloud
from icuhub.connectors.prisma_cloud.models import DismissAlertInput, SnoozeAlertInput
from icuhub.kit.errors import OutcomeUnknown, StalePlan
from icuhub.kit.testing import ReadOnlyGuard, RouteTransport, make_connector

from .conftest import CSPM_CONFIG, CSPM_LOGIN, SECRETS, cspm_connector, load_fixture


def test_dismiss_plan_is_read_only_and_hashes_current_state() -> None:
    alert = load_fixture("cspm_alert.json")
    routes = {
        ("POST", "/login"): CSPM_LOGIN,
        ("GET", "/alert/alert-100"): {"status": 200, "json": alert},
        ("POST", "/alert/dismiss"): {"status": 200, "json": {"dismissed": True}},
    }
    connector = make_connector(
        PrismaCloud,
        CSPM_CONFIG,
        ReadOnlyGuard(RouteTransport(routes), allowed_post_paths=("/login",)),
        SECRETS,
    )
    plan = asyncio.run(connector.plan_dismiss_alert(DismissAlertInput(alert_id="alert-100", note="approved")))
    assert plan.changed is True
    assert plan.request["method"] == "POST"
    assert plan.preconditions["expected_status"] == "open"


def test_dismiss_current_state_is_no_op() -> None:
    alert = dict(load_fixture("cspm_alert.json"))
    alert["status"] = "dismissed"
    connector = cspm_connector({("GET", "/alert/alert-100"): {"status": 200, "json": alert}})
    plan = asyncio.run(connector.plan_dismiss_alert(DismissAlertInput(alert_id="alert-100", note="approved")))
    assert plan.changed is False
    outcome = asyncio.run(connector.apply_dismiss_alert(plan))
    assert outcome.status == "no_op"


def test_dismiss_apply_detects_stale_plan() -> None:
    original = load_fixture("cspm_alert.json")
    changed = dict(original)
    changed["status"] = "resolved"
    states = iter((original, changed))
    connector = cspm_connector({("GET", "/alert/alert-100"): lambda _request: {"status": 200, "json": next(states)}})
    plan = asyncio.run(connector.plan_dismiss_alert(DismissAlertInput(alert_id="alert-100", note="approved")))
    with pytest.raises(StalePlan):
        asyncio.run(connector.apply_dismiss_alert(plan))


def test_dismiss_transport_ambiguity_is_outcome_unknown() -> None:
    alert = load_fixture("cspm_alert.json")

    def ambiguous(_request: Any) -> dict[str, Any]:
        raise OutcomeUnknown(idempotency_key="test")

    connector = cspm_connector({
        ("GET", "/alert/alert-100"): {"status": 200, "json": alert},
        ("POST", "/alert/dismiss"): ambiguous,
    })
    plan = asyncio.run(connector.plan_dismiss_alert(DismissAlertInput(alert_id="alert-100", note="approved")))
    outcome = asyncio.run(connector.apply_dismiss_alert(plan))
    assert outcome.status == "outcome_unknown"


def test_snooze_requires_future_window() -> None:
    with pytest.raises(ValueError):
        SnoozeAlertInput(alert_id="alert-100", dismiss_until="2020-01-01T00:00:00Z", note="expired")
