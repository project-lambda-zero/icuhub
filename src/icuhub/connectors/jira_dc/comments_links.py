"""Pure Jira Data Center comment, remote-link, and metadata operation helpers."""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import Field

from icuhub.connectors._jira.helpers import list_field
from icuhub.connectors._jira.models import StrictModel
from icuhub.kit.errors import VendorContractError

__all__ = [
    "AddRemoteLinkArgs",
    "GetEditMetadataArgs",
    "GetEditMetadataOutput",
    "ListCommentsArgs",
    "ListCommentsOutput",
    "ListFieldsArgs",
    "ListFieldsOutput",
    "ListProjectsArgs",
    "ListProjectsOutput",
    "ListRemoteLinksArgs",
    "ListRemoteLinksOutput",
    "UpdateCommentArgs",
    "comment_body_digest",
    "comment_body_matches",
    "comment_page",
    "comment_update_payload",
    "edit_metadata_fields",
    "field_list",
    "find_remote_link",
    "next_comment_offset",
    "persisted_remote_link_id",
    "project_list",
    "remote_link_list",
    "remote_link_payload",
]


class UpdateCommentArgs(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    comment_id: str = Field(min_length=1)
    expected_updated: str = Field(min_length=1)
    body: str


class AddRemoteLinkArgs(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    global_id: str = Field(min_length=1, max_length=2048)
    url: str = Field(min_length=1, max_length=2048)
    title: str = Field(min_length=1, max_length=1024)
    relationship: str | None = Field(default=None, min_length=1, max_length=255)


class ListCommentsArgs(StrictModel):
    issue_id_or_key: str = Field(min_length=1)
    start_at: int = Field(default=0, ge=0)
    max_results: int = Field(default=100, ge=1, le=1000)


class ListCommentsOutput(StrictModel):
    comments: list[dict[str, Any]]
    next_start_at: int | None = None


class ListRemoteLinksArgs(StrictModel):
    issue_id_or_key: str = Field(min_length=1)


class ListRemoteLinksOutput(StrictModel):
    links: list[dict[str, Any]]


class GetEditMetadataArgs(StrictModel):
    issue_id_or_key: str = Field(min_length=1)


class GetEditMetadataOutput(StrictModel):
    fields: dict[str, Any]


class ListFieldsArgs(StrictModel):
    pass


class ListFieldsOutput(StrictModel):
    fields: list[dict[str, Any]]


class ListProjectsArgs(StrictModel):
    pass


class ListProjectsOutput(StrictModel):
    projects: list[dict[str, Any]]


def comment_body_digest(body: str) -> str:
    """Return the body component of the update action's natural key."""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def comment_update_payload(body: str) -> dict[str, str]:
    """Build a Data Center plain or wiki string body, never an ADF document."""
    return {"body": body}


def comment_body_matches(comment: dict[str, Any], expected_body: str) -> bool:
    """Match only a persisted string body, rejecting structured ADF lookalikes."""
    return isinstance(comment.get("body"), str) and comment["body"] == expected_body


def comment_page(body: Any) -> list[dict[str, Any]]:
    """Extract one comment page without consulting the mutable total field."""
    return list_field(body, "comments")


def next_comment_offset(start_at: int, returned_count: int, max_results: int) -> int | None:
    """Continue only after a full page, advancing by the number actually returned."""
    if returned_count == 0 or returned_count < max_results:
        return None
    return start_at + returned_count


def remote_link_payload(args: AddRemoteLinkArgs) -> dict[str, Any]:
    """Build the vendor create payload from a caller-supplied deterministic global ID."""
    payload: dict[str, Any] = {
        "globalId": args.global_id,
        "object": {"url": args.url, "title": args.title},
    }
    if args.relationship is not None:
        payload["relationship"] = args.relationship
    return payload


def _object_list(body: Any, what: str) -> list[dict[str, Any]]:
    if not isinstance(body, list) or any(not isinstance(item, dict) for item in body):
        raise VendorContractError(f"{what} must be an array of objects")
    return body


def remote_link_list(body: Any) -> list[dict[str, Any]]:
    return _object_list(body, "Jira remote link listing")


def field_list(body: Any) -> list[dict[str, Any]]:
    return _object_list(body, "Jira field listing")


def project_list(body: Any) -> list[dict[str, Any]]:
    return _object_list(body, "Jira project listing")


def find_remote_link(links: list[dict[str, Any]], global_id: str) -> dict[str, Any] | None:
    """Find a remote link by its exact deterministic global ID."""
    return next((link for link in links if link.get("globalId") == global_id), None)


def persisted_remote_link_id(link: dict[str, Any]) -> str | None:
    """Normalize Jira's string or numeric remote-link identifier for outcome identity."""
    value = link.get("id")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value:
        return value
    return None


def edit_metadata_fields(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict) or not isinstance(body.get("fields"), dict):
        raise VendorContractError("Jira edit metadata must carry a fields object")
    return body["fields"]
