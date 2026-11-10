"""End-to-end kit proof for the sample tracker: stream paging, mapping to golden, webhook verification."""

import asyncio
import hashlib
import hmac
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from icuhub.kit.errors import VendorContractError, WebhookRejected
from icuhub.kit.testing import (
    RouteTransport,
    amake_connector,
    assert_matches_golden,
    collect_stream,
    make_connector,
    map_all,
)
from icuhub.kit.types import WebhookDelivery
from tests.kit.sample_tracker import SampleTracker

GOLDEN = Path(__file__).parent / "golden" / "tickets.json"
BASE = "https://tracker.example.test"
TOKEN_REF = "cred:tracker-token"
WEBHOOK_SECRET = b"whsec-fixture"
NOW = datetime(2026, 11, 9, 12, 0, 0, tzinfo=UTC)

ISSUES: list[dict[str, Any]] = [
    {
        "key": "SMP-101",
        "summary": "Login page returns 500",
        "status": "In Progress",
        "version": 4,
        "resolution": None,
        "web_url": "https://tracker.example.test/browse/SMP-101",
        "updated_at": "2026-11-01T02:00:00Z",
        "labels": ["auth", "p1"],
    },
    {
        "key": "SMP-102",
        "summary": "Rotate export key",
        "status": "Done",
        "version": 7,
        "resolution": "Fixed",
        "web_url": None,
        "updated_at": "2026-11-01T02:05:00Z",
        "labels": [],
    },
]


def _connector() -> SampleTracker:
    transport = RouteTransport({("GET", "/api/issues"): {"status": 200, "json": {"issues": ISSUES}}})
    return make_connector(
        SampleTracker,
        {"base_url": BASE, "api_token": {"ref": TOKEN_REF}},
        transport,
        {TOKEN_REF: b"fixture-token"},
    )


def test_amake_connector_builds_inside_a_running_loop() -> None:
    async def build() -> SampleTracker:
        transport = RouteTransport({("GET", "/api/issues"): {"status": 200, "json": {"issues": ISSUES}}})
        return await amake_connector(
            SampleTracker,
            {"base_url": BASE, "api_token": {"ref": TOKEN_REF}},
            transport,
            {TOKEN_REF: b"fixture-token"},
        )

    connector = asyncio.run(build())
    assert connector.ctx.http is not None


def test_tickets_stream_maps_to_golden() -> None:
    connector = _connector()
    batches = collect_stream(connector, "tickets")
    assert [batch.complete for batch in batches] == [False]
    records = [raw for batch in batches for raw in batch.records]
    assert records == ISSUES
    assert_matches_golden(map_all(connector, "tickets", records), GOLDEN)


def test_mapper_rejects_a_shape_mismatch() -> None:
    connector = _connector()
    bad = {**ISSUES[0], "version": "4"}
    with pytest.raises(VendorContractError, match="version must be an integer"):
        map_all(connector, "tickets", [bad])


def test_webhook_verifier_accepts_signed_body_and_rejects_tampering() -> None:
    connector = _connector()
    verifier = connector.webhook_verifier(WEBHOOK_SECRET)
    assert verifier is not None
    body = b'{"key": "SMP-101"}'
    signature = "sha256=" + hmac.new(WEBHOOK_SECRET, body, hashlib.sha256).hexdigest()
    headers = {"X-Tracker-Signature": signature, "X-Tracker-Delivery": "d-1", "X-Tracker-Event": "issue.updated"}

    verified = verifier.verify(WebhookDelivery(headers=headers, body=body, received_at=NOW), now=NOW)
    assert verified.delivery_id == "d-1"
    assert verified.event_type == "issue.updated"

    tampered = WebhookDelivery(headers=headers, body=b'{"key": "SMP-999"}', received_at=NOW)
    with pytest.raises(WebhookRejected, match="invalid webhook signature"):
        verifier.verify(tampered, now=NOW)
