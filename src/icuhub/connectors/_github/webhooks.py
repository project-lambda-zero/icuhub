"""GitHub webhook hint parsing.

A verified delivery only tells the connector that something changed. Each hint names the
canonical stream to re-read through the REST API with ``reconcile`` set, so the authoritative
read path, not the webhook body, produces the stored record.
"""

from __future__ import annotations

import json
from typing import Any

from icuhub.connectors._github.base import GITHUB_DELIVERY_HEADER
from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import StreamRecord, WebhookDelivery

__all__ = ["GITHUB_WEBHOOK_EVENTS", "hints_for_delivery"]

# GitHub event name -> canonical stream to reconcile. Events outside this table are not ours.
_EVENT_STREAMS: dict[str, tuple[str, ...]] = {
    "code_scanning_alert": ("code_scanning_alerts",),
    "dependabot_alert": ("dependabot_alerts",),
    "secret_scanning_alert": ("secret_scanning_alerts",),
    "branch_protection_rule": ("branch_protection",),
    "push": ("branches", "commits"),
    "workflow_run": ("workflow_runs",),
    "workflow_job": ("workflow_jobs",),
    "pull_request": ("pull_requests",),
    "pull_request_review": ("reviews",),
    "pull_request_review_comment": ("review_comments",),
    "repository": ("repositories",),
    "organization": ("organizations",),
    "team": ("teams",),
    "member": ("collaborators",),
}

GITHUB_WEBHOOK_EVENTS: tuple[str, ...] = tuple(sorted(_EVENT_STREAMS))


def hints_for_delivery(event: str, delivery: WebhookDelivery) -> list[StreamRecord]:
    """Return one incremental reconcile hint per stream named by ``event``.

    The body is parsed only to reject malformed JSON and to bind the hint to its repository.
    Records are never produced from the body itself.
    """
    streams = _EVENT_STREAMS.get(event)
    if streams is None:
        return []
    try:
        value: Any = json.loads(delivery.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VendorContractError("GitHub webhook body must be JSON") from exc
    if not isinstance(value, dict):
        raise VendorContractError("GitHub webhook body must be a JSON object")
    delivery_id = delivery.headers.get(GITHUB_DELIVERY_HEADER, "")
    if not delivery_id:
        raise VendorContractError("GitHub webhook delivery lacks X-GitHub-Delivery")
    repository = value.get("repository")
    repository_id = repository.get("id") if isinstance(repository, dict) else None
    return [
        StreamRecord(
            stream=stream,
            raw={"event": event, "delivery_id": delivery_id, "repository_id": repository_id},
            reconcile="incremental",
        )
        for stream in streams
    ]
