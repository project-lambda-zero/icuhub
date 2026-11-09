"""Edition-neutral Jira helpers shared by the Cloud and Data Center connectors.

Everything here is pure: no HTTP, no connector state. Edition-specific REST paths, pagination,
and auth stay in each connector package.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any
from urllib.parse import quote

from icuhub.connectors._jira import mappers as jira
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.errors import StalePlan, VendorContractError

__all__ = [
    "ROUTE_LABEL_PREFIX",
    "audit_id",
    "audit_ts",
    "changelog_histories",
    "comment_marker",
    "comment_ts",
    "digest",
    "history_ts",
    "issue_state",
    "issue_updated",
    "link_exists",
    "list_field",
    "multipart",
    "record_id",
    "require_field",
    "route_label",
    "seg",
    "status_changed_to",
    "strip_order",
    "time_cursor",
    "value_matches",
]

ROUTE_LABEL_PREFIX = "icuhub-"


def seg(value: str) -> str:
    """Percent-encode a single URL path segment."""
    return quote(value, safe="")


def digest(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


def route_label(route_key: str) -> str:
    return ROUTE_LABEL_PREFIX + digest(route_key)[:32]


def comment_marker(action_key: str) -> str:
    return f"[icuhub-action:{action_key}]"


def time_cursor(checkpoint: Any) -> TimeIdCursor:
    return checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)


def list_field(body: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(body, dict) or not isinstance(body.get(key), list):
        raise VendorContractError(f"Jira response must carry a '{key}' list")
    return body[key]


def strip_order(jql: str) -> str:
    index = jql.upper().find("ORDER BY")
    return (jql if index < 0 else jql[:index]).strip()


def issue_updated(raw: dict[str, Any]) -> datetime:
    fields = raw.get("fields")
    if not isinstance(fields, dict):
        raise VendorContractError("Jira issue fields must be an object")
    return jira.parse_time(jira.required_str(fields, "updated"), "fields.updated")


def comment_ts(raw: dict[str, Any]) -> datetime:
    value = raw.get("updated") or raw.get("created")
    if not isinstance(value, str):
        raise VendorContractError("Jira comment carries no timestamp")
    return jira.parse_time(value, "comment.updated")


def history_ts(raw: dict[str, Any]) -> datetime:
    return jira.parse_time(jira.required_str(raw, "created"), "history.created")


def audit_ts(raw: dict[str, Any]) -> datetime:
    return jira.parse_time(jira.required_str(raw, "created"), "auditRecord.created")


def audit_id(raw: dict[str, Any]) -> str:
    value = raw.get("id")
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise VendorContractError("Jira audit record carries no id")
    return str(value)


def record_id(raw: dict[str, Any]) -> str:
    return jira.required_str(raw, "id")


def changelog_histories(issue: dict[str, Any]) -> list[dict[str, Any]]:
    changelog = issue.get("changelog")
    if not isinstance(changelog, dict) or not isinstance(changelog.get("histories"), list):
        raise VendorContractError("Jira search with expand=changelog must carry changelog.histories")
    return changelog["histories"]


def issue_state(issue: dict[str, Any]) -> dict[str, str]:
    fields = issue.get("fields")
    if not isinstance(fields, dict):
        raise VendorContractError("Jira issue fields must be an object")
    status = fields.get("status")
    status_name = status.get("name") if isinstance(status, dict) else None
    return {
        "id": jira.required_str(issue, "id"),
        "updated": jira.required_str(fields, "updated"),
        "status": status_name if isinstance(status_name, str) else "",
    }


def status_changed_to(issue: dict[str, Any], target: str) -> bool:
    changelog = issue.get("changelog")
    histories = changelog.get("histories", []) if isinstance(changelog, dict) else []
    for history in histories:
        for item in history.get("items", []) if isinstance(history, dict) else []:
            if isinstance(item, dict) and item.get("field") == "status" and item.get("toString") == target:
                return True
    return False


def link_exists(issue: dict[str, Any], link_type: str, outward_key: str) -> bool:
    fields = issue.get("fields")
    links = fields.get("issuelinks", []) if isinstance(fields, dict) else []
    for link in links if isinstance(links, list) else []:
        if not isinstance(link, dict):
            continue
        type_block = link.get("type")
        outward = link.get("outwardIssue")
        if (
            isinstance(type_block, dict)
            and type_block.get("name") == link_type
            and isinstance(outward, dict)
            and outward.get("key") == outward_key
        ):
            return True
    return False


def value_matches(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and value_matches(value, actual[key]) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return (
            isinstance(actual, list)
            and len(expected) == len(actual)
            and all(value_matches(e, a) for e, a in zip(expected, actual, strict=True))
        )
    return expected == actual


def require_field(body: dict[str, Any], field: str, expected: str, what: str) -> None:
    if body.get(field) != expected:
        raise StalePlan(f"Jira {what} {field} changed since the plan was made")


def multipart(boundary: str, filename: str, media_type: str, content: bytes) -> bytes:
    escaped = filename.replace('"', '\\"')
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{escaped}"\r\n'
        f"Content-Type: {media_type}\r\n\r\n"
    ).encode()
    return head + content + f"\r\n--{boundary}--\r\n".encode()
