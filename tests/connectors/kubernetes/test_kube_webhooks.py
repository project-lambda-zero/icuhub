"""Kubernetes audit webhook parsing: EventList bodies become dedupe-keyed audit_events records."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from icuhub.connectors._kube.webhooks import (
    KUBE_AUDIT_RECORD_KIND,
    KUBE_AUDIT_STREAM,
    KUBE_WEBHOOK_EVENTS,
    audit_hints_for_delivery,
)
from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import WebhookDelivery

RECEIVED = datetime(2026, 11, 10, tzinfo=UTC)


def delivery(body: bytes) -> WebhookDelivery:
    return WebhookDelivery(headers={}, body=body, received_at=RECEIVED)


def event_list(*items: Any) -> bytes:
    return json.dumps({"kind": "EventList", "apiVersion": "audit.k8s.io/v1", "items": list(items)}).encode()


def audit_item(audit_id: str = "a-1", stage: str = "ResponseComplete") -> dict[str, Any]:
    return {
        "kind": "Event",
        "auditID": audit_id,
        "stage": stage,
        "verb": "delete",
        "user": {"username": "system:serviceaccount:ops:bot"},
        "objectRef": {"resource": "pods", "namespace": "default", "name": "api"},
        "responseStatus": {"code": 200},
    }


def test_webhook_accepts_all_event_headers() -> None:
    assert KUBE_WEBHOOK_EVENTS == ("*",)


def test_each_audit_item_becomes_a_keyed_audit_event_record() -> None:
    records = audit_hints_for_delivery(
        delivery(event_list(audit_item("a-1", "RequestReceived"), audit_item("a-1", "ResponseComplete"))),
        "kube-apiserver",
    )
    assert [record.stream for record in records] == [KUBE_AUDIT_STREAM, KUBE_AUDIT_STREAM]
    assert [record.raw["_dedupe_key"] for record in records] == [
        "kube-apiserver:a-1:RequestReceived",
        "kube-apiserver:a-1:ResponseComplete",
    ]
    first = records[0].raw
    assert first["_record_kind"] == KUBE_AUDIT_RECORD_KIND
    assert first["_api_source"] == "kube-apiserver"
    assert first["verb"] == "delete"
    assert first["objectRef"]["name"] == "api"


def test_empty_event_list_yields_no_records() -> None:
    assert audit_hints_for_delivery(delivery(event_list()), "kube-apiserver") == []


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        json.dumps({"kind": "Event", "items": []}).encode(),
        json.dumps({"kind": "EventList", "items": "nope"}).encode(),
        event_list("not-an-object"),
    ],
)
def test_malformed_bodies_are_contract_errors(body: bytes) -> None:
    with pytest.raises(VendorContractError):
        audit_hints_for_delivery(delivery(body), "kube-apiserver")


@pytest.mark.parametrize("missing", ["auditID", "stage"])
def test_items_without_identity_are_contract_errors(missing: str) -> None:
    item = audit_item()
    del item[missing]
    with pytest.raises(VendorContractError):
        audit_hints_for_delivery(delivery(event_list(item)), "kube-apiserver")
