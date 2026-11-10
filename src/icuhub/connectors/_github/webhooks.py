"""GitHub webhook hint parsing.

A verified delivery only tells the connector that something changed. Each hint names the
canonical stream to re-read through the REST API with ``reconcile`` set, so the authoritative
read path, not the webhook body, produces the stored record.
"""

from __future__ import annotations

import json
import re
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
    "check_run": ("check_runs",),
    "check_suite": ("check_runs",),
    "status": ("commit_statuses",),
}

GITHUB_WEBHOOK_EVENTS: tuple[str, ...] = tuple(sorted(_EVENT_STREAMS))

# Commit-scoped events carry the commit whose check runs or statuses must be re-read.
_COMMIT_EVENTS = frozenset({"check_run", "check_suite", "status"})
# Check runs and suites are written only through GitHub App auth, so the App ID identifies our own writes.
_APP_EVENTS = frozenset({"check_run", "check_suite"})
# Commit statuses have no App identity; ICUHUB writes its statuses under this context namespace.
ICUHUB_STATUS_CONTEXT_PREFIX = "icuhub/"
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _echo_of_own_write(event: str, value: dict[str, Any], app_id: str | None) -> bool:
    """True when the delivery reports a change ICUHUB itself wrote, so re-reading it adds nothing."""
    if event in _APP_EVENTS:
        obj = value.get(event)
        app = obj.get("app") if isinstance(obj, dict) else None
        return app_id is not None and isinstance(app, dict) and str(app.get("id")) == app_id
    if event == "status":
        context = value.get("context")
        return isinstance(context, str) and context.startswith(ICUHUB_STATUS_CONTEXT_PREFIX)
    return False


def _commit_sha(event: str, value: dict[str, Any]) -> str:
    if event == "status":
        sha = value.get("sha")
    else:
        nested = value.get(event)
        sha = nested.get("head_sha") if isinstance(nested, dict) else None
    if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
        raise VendorContractError(f"GitHub {event} webhook lacks a full commit SHA")
    return sha


def hints_for_delivery(event: str, delivery: WebhookDelivery, *, app_id: str | None = None) -> list[StreamRecord]:
    """Return one incremental reconcile hint per stream named by ``event``.

    The body is parsed only to reject malformed JSON, to bind the hint to its repository (a numeric
    repository ID sets ``target_uid``, otherwise None), and to name the commit for commit-scoped
    events. Records are never produced from the body itself. Deliveries reporting ICUHUB's own
    writes (matching ``app_id`` for check runs and suites, ICUHUB status context prefix for statuses)
    produce no hints.
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
    if _echo_of_own_write(event, value, app_id):
        return []
    repository = value.get("repository")
    repository_id = repository.get("id") if isinstance(repository, dict) else None
    target_uid = str(repository_id) if isinstance(repository_id, int) and not isinstance(repository_id, bool) else None
    raw: dict[str, Any] = {"event": event, "delivery_id": delivery_id, "repository_id": repository_id}
    if event in _COMMIT_EVENTS:
        raw["commit_sha"] = _commit_sha(event, value)
    return [
        StreamRecord(
            stream=stream,
            raw=dict(raw),
            target_uid=target_uid,
            reconcile="incremental",
        )
        for stream in streams
    ]
