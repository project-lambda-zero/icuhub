"""Verified-delivery parsing for Jira issue and comment events."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from icuhub.kit.errors import VendorContractError
from icuhub.kit.types import StreamRecord, WebhookDelivery

EVENT_TYPES = (
    "jira:issue_created",
    "jira:issue_updated",
    "jira:issue_deleted",
    "comment_created",
    "comment_updated",
    "comment_deleted",
)


def _payload(delivery: WebhookDelivery) -> dict[str, Any]:
    try:
        value = json.loads(delivery.body)
    except ValueError as exc:
        raise VendorContractError("Jira webhook body is not valid JSON") from exc
    if not isinstance(value, dict):
        raise VendorContractError("Jira webhook body must be an object")
    return value


def _event_type(payload: dict[str, Any], delivery: WebhookDelivery) -> str:
    event = payload.get("webhookEvent") or delivery.headers.get("x-atlassian-webhook-event")
    if event not in EVENT_TYPES:
        raise VendorContractError("unsupported Jira webhook event")
    return str(event)


def _property_value(container: dict[str, Any], key: str) -> Any:
    properties = container.get("properties")
    if isinstance(properties, dict):
        entry = properties.get(key)
        if isinstance(entry, dict) and "value" in entry:
            return entry["value"]
        return entry
    if isinstance(properties, list):
        for entry in properties:
            if isinstance(entry, dict) and entry.get("key") == key:
                return entry.get("value")
    return None


def _delivery_key(payload: dict[str, Any], delivery: WebhookDelivery, connection_id: str) -> str:
    supplied = delivery.headers.get("x-atlassian-webhook-identifier")
    if supplied:
        return supplied
    issue = payload.get("issue") if isinstance(payload.get("issue"), dict) else {}
    comment = payload.get("comment") if isinstance(payload.get("comment"), dict) else {}
    changelog = payload.get("changelog") if isinstance(payload.get("changelog"), dict) else {}
    fields = issue.get("fields")
    updated = fields.get("updated") if isinstance(fields, dict) else None
    digest = hashlib.sha256(delivery.body).hexdigest()
    parts = (
        connection_id,
        str(payload.get("webhookEvent") or "unknown"),
        str(payload.get("timestamp") or updated or "unknown"),
        str(issue.get("id") or "unknown"),
        str(changelog.get("id") or "unknown"),
        str(comment.get("id") or "unknown"),
        digest,
    )
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def parse_jira_delivery(
    delivery: WebhookDelivery,
    *,
    installation: str,
    base_url: str,
    connection_id: str,
) -> list[StreamRecord]:
    payload = _payload(delivery)
    event = _event_type(payload, delivery)
    issue = payload.get("issue")
    if not isinstance(issue, dict) or not isinstance(issue.get("id"), str):
        raise VendorContractError("Jira webhook must contain an issue with a stable id")
    enriched_issue = {
        **issue,
        "_jira_installation": installation,
        "_jira_base_url": base_url,
        "_icuhub_delivery_key": _delivery_key(payload, delivery, connection_id),
    }
    fields = enriched_issue.get("fields")
    project = fields.get("project") if isinstance(fields, dict) else None
    project_id = project.get("id") if isinstance(project, dict) else None
    target_uid = f"jira_project:{installation}/{project_id}" if project_id is not None else None
    records: list[StreamRecord] = []
    is_comment_event = event.startswith("comment_")
    if not is_comment_event:
        own_issue_echo = (
            event == "jira:issue_updated"
            and _property_value(enriched_issue, "icuhub.action_key") is not None
            and not payload.get("changelog")
        )
        if not own_issue_echo:
            records.append(
                StreamRecord(
                    stream="issues",
                    raw=enriched_issue,
                    target_uid=target_uid,
                    event="delete" if event == "jira:issue_deleted" else "upsert",
                )
            )
    changelog = payload.get("changelog")
    if isinstance(changelog, dict) and isinstance(changelog.get("id"), str):
        history = {
            **changelog,
            "_jira_issue": {"id": issue["id"], "key": issue.get("key")},
            "_jira_installation": installation,
            "_icuhub_delivery_key": _delivery_key(payload, delivery, connection_id),
        }
        records.append(StreamRecord(stream="issue_changelogs", raw=history, target_uid=target_uid))
    comment = payload.get("comment")
    if isinstance(comment, dict) and isinstance(comment.get("id"), str):
        own_comment_echo = _property_value(comment, "icuhub.action_key") is not None
        if not own_comment_echo:
            enriched_comment = {
                **comment,
                "_jira_issue": {"id": issue["id"], "key": issue.get("key")},
                "_jira_installation": installation,
                "_icuhub_delivery_key": _delivery_key(payload, delivery, connection_id),
            }
            records.append(
                StreamRecord(
                    stream="comments",
                    raw=enriched_comment,
                    target_uid=target_uid,
                    event="delete" if event == "comment_deleted" else "upsert",
                )
            )
    return records
