"""Invicti Enterprise governed triage and authenticated webhook tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime

import httpx2
import pytest

from icuhub.connectors.invicti_enterprise.models import UpdateIssueInput
from icuhub.kit.errors import StalePlan, WebhookRejected
from icuhub.kit.testing import map_all
from icuhub.kit.types import WebhookDelivery

from .conftest import enterprise_connector, load_fixture

_ISSUE_ID = "6dc7a92f-94ab-4f7c-b60f-000000000301"


def _args(**changes) -> UpdateIssueInput:
    values = {
        "issue_id": _ISSUE_ID,
        "expected_last_seen": datetime(2026, 11, 1, 11, 0, tzinfo=UTC),
        "expected_state": "Present",
        **changes,
    }
    return UpdateIssueInput(**values)


def test_update_issue_plan_apply_and_read_back() -> None:
    state = deepcopy(load_fixture("issues.json")["List"][0])
    state["Assignee"] = "old@example.test"
    sent = []

    def get_issue(request):
        return {"status": 200, "json": state}

    def put_issue(request):
        payload = json.loads(request.content)
        sent.append(payload)
        state.update(payload)
        return {"status": 204}

    connector = enterprise_connector(
        {
            ("GET", f"/api/1.0/issues/{_ISSUE_ID}"): get_issue,
            ("PUT", f"/api/1.0/issues/{_ISSUE_ID}"): put_issue,
        }
    )
    plan = asyncio.run(connector.plan_update_issue(_args(state="AcceptedRisk", assignee="new@example.test", tags=["production", "triaged"])))
    assert plan.changed is True
    assert plan.diff["after"]["State"] == "AcceptedRisk"
    outcome = asyncio.run(connector.apply_update_issue(plan))
    assert outcome.status == "succeeded"
    assert sent == [{"State": "AcceptedRisk", "Assignee": "new@example.test", "Tags": ["production", "triaged"]}]
    assert outcome.result["issue"]["assignee"] == "new@example.test"


def test_update_issue_no_op_and_stale_plan() -> None:
    raw = load_fixture("issues.json")["List"][0]
    connector = enterprise_connector({("GET", f"/api/1.0/issues/{_ISSUE_ID}"): {"status": 200, "json": raw}})
    no_op = asyncio.run(connector.plan_update_issue(_args(state="Present", tags=["production"])))
    assert no_op.changed is False
    assert asyncio.run(connector.apply_update_issue(no_op)).status == "no_op"
    with pytest.raises(StalePlan):
        asyncio.run(connector.plan_update_issue(_args(state="AcceptedRisk", expected_state="FalsePositive")))


def test_update_issue_transport_uncertainty_is_not_blind_retried() -> None:
    raw = load_fixture("issues.json")["List"][0]

    def failed_put(request):
        raise httpx2.ConnectError("simulated transport uncertainty")

    connector = enterprise_connector(
        {
            ("GET", f"/api/1.0/issues/{_ISSUE_ID}"): {"status": 200, "json": raw},
            ("PUT", f"/api/1.0/issues/{_ISSUE_ID}"): failed_put,
        }
    )
    plan = asyncio.run(connector.plan_update_issue(_args(state="AcceptedRisk")))
    outcome = asyncio.run(connector.apply_update_issue(plan))
    assert outcome.status == "outcome_unknown"


def test_static_webhook_retains_receipt_and_requests_canonical_full_sync() -> None:
    connector = enterprise_connector({})
    verifier = connector.webhook_verifier(b"high-entropy-token")
    body = json.dumps(load_fixture("report.json")).encode()
    delivery = WebhookDelivery(
        headers={"x-icuhub-token": "high-entropy-token"}, body=body, received_at=datetime(2026, 11, 10, tzinfo=UTC)
    )
    verifier.verify(delivery, now=delivery.received_at)
    with pytest.raises(WebhookRejected):
        verifier.verify(
            WebhookDelivery(headers={"x-icuhub-token": "bad"}, body=body, received_at=delivery.received_at),
            now=delivery.received_at,
        )
    records = connector.receive_event(delivery)
    assert [record.stream for record in records] == ["webhook_receipts", "issues"]
    assert records[1].reconcile == "full"
    receipt = records[0].raw
    assert base64.b64decode(receipt["raw_body_base64"]) == body
    assert receipt["integration_id"] == "default"
    mapped = map_all(connector, "webhook_receipts", [receipt])[0]
    assert mapped.data["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert "raw_body_base64" not in mapped.data


def test_basic_webhook_auth_and_single_issue_dedupe_identity() -> None:
    connector = enterprise_connector({}, webhook_mode="basic_auth")
    verifier = connector.webhook_verifier(b"operator:password")
    issue = load_fixture("issues.json")["List"][0]
    body = json.dumps(issue).encode()
    credentials = base64.b64encode(b"operator:password").decode()
    delivery = WebhookDelivery(
        headers={"authorization": f"Basic {credentials}"}, body=body, received_at=datetime(2026, 11, 10, tzinfo=UTC)
    )
    verifier.verify(delivery, now=delivery.received_at)
    first = connector.receive_event(delivery)
    replay = connector.receive_event(delivery)
    assert first[0].raw["delivery_id"] == replay[0].raw["delivery_id"]
    assert first[1].reconcile == "full"
