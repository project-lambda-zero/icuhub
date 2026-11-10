"""Kubernetes and OpenShift audit webhook parsing.

The API server audit webhook posts an ``audit.k8s.io`` EventList. Each item is one audit event
that becomes a telemetry record. Audit events cannot be re-read through the API, so the parsed
items are emitted directly, with the dedupe identity ``API source + auditID + stage`` preserved.
"""

from __future__ import annotations

import json
from typing import Any

from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import StreamRecord, WebhookDelivery

__all__ = ["KUBE_AUDIT_RECORD_KIND", "KUBE_AUDIT_STREAM", "KUBE_WEBHOOK_EVENTS", "audit_hints_for_delivery"]

KUBE_AUDIT_STREAM = "audit_events"
KUBE_AUDIT_RECORD_KIND = "audit_event"
_EVENT_LIST_KIND = "EventList"

# The audit receiver sends no event header, so the verifier yields event_type None and only the
# wildcard matches. The body kind is checked in audit_hints_for_delivery instead.
KUBE_WEBHOOK_EVENTS: tuple[str, ...] = ("*",)


def _require_text(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        raise VendorContractError(f"Kubernetes audit event lacks {key}")
    return value


def audit_hints_for_delivery(delivery: WebhookDelivery, api_source: str) -> list[StreamRecord]:
    """Return one ``audit_events`` record per audit item in an EventList delivery.

    ``api_source`` is the configured authoritative API source, because the EventList body does
    not carry one. Every record carries ``_dedupe_key`` = ``api_source:auditID:stage`` so replays
    of the same event collapse at commit time, across webhook, file, and managed transports.
    """
    try:
        value: Any = json.loads(delivery.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VendorContractError("Kubernetes audit webhook body must be JSON") from exc
    if not isinstance(value, dict):
        raise VendorContractError("Kubernetes audit webhook body must be a JSON object")
    if value.get("kind") != _EVENT_LIST_KIND:
        raise VendorContractError(f"Kubernetes audit webhook body kind must be {_EVENT_LIST_KIND}")
    items = value.get("items")
    if not isinstance(items, list):
        raise VendorContractError("Kubernetes audit EventList items must be a list")

    records: list[StreamRecord] = []
    for item in items:
        if not isinstance(item, dict):
            raise VendorContractError("Kubernetes audit EventList item must be a JSON object")
        audit_id = _require_text(item, "auditID")
        stage = _require_text(item, "stage")
        raw: dict[str, Any] = {
            **item,
            "_record_kind": KUBE_AUDIT_RECORD_KIND,
            "_api_source": api_source,
            "_dedupe_key": f"{api_source}:{audit_id}:{stage}",
        }
        records.append(StreamRecord(stream=KUBE_AUDIT_STREAM, raw=raw, reconcile=None))
    return records
