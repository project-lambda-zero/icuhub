"""Attachment inventory, metadata, and bounded content reads for Jira Data Center."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncIterator
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from icuhub.connectors._jira import mappers as jira
from icuhub.connectors._jira.helpers import record_id, seg, time_cursor
from icuhub.kit._urls import normalize_base_url, resolve_request_url
from icuhub.kit.errors import ConfigError, UnsafeUrl, VendorContractError
from icuhub.kit.types import MapContext, RawBatch, SourceRecord

if TYPE_CHECKING:
    from icuhub.connectors.jira_dc.connector import JiraDataCenter

__all__ = [
    "DownloadAttachmentArgs",
    "DownloadAttachmentOutput",
    "GetAttachmentArgs",
    "GetAttachmentOutput",
    "attachment_records",
    "attachment_ts",
    "download_attachment",
    "get_attachment",
    "map_attachment",
    "stream_attachments",
    "validate_content_url",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GetAttachmentArgs(_StrictModel):
    attachment_id: str = Field(min_length=1)


class GetAttachmentOutput(_StrictModel):
    attachment_id: str
    filename: str
    media_type: str | None
    size: int = Field(ge=0)
    created: str | None
    author: dict[str, Any] | None
    self_url: str | None
    content_url: str
    thumbnail_url: str | None


class DownloadAttachmentArgs(_StrictModel):
    attachment_id: str = Field(min_length=1)


class DownloadAttachmentOutput(_StrictModel):
    attachment_id: str
    filename: str
    media_type: str | None
    size: int = Field(ge=0)
    sha256: str
    content_base64: str


def attachment_ts(raw: dict[str, Any]) -> datetime:
    return jira.parse_time(raw.get("created"), "attachment.created")


def attachment_records(issue: dict[str, Any], parent: dict[str, str]) -> list[dict[str, Any]]:
    """Flatten one issue attachment field and retain the parent identity on each item."""
    fields = issue.get("fields")
    if not isinstance(fields, dict):
        raise VendorContractError("Jira issue detail fields must be an object")
    found = fields.get("attachment")
    if not isinstance(found, list):
        raise VendorContractError("Jira issue attachment field must be a list")
    records: list[dict[str, Any]] = []
    for item in found:
        if not isinstance(item, dict):
            raise VendorContractError("Jira issue attachment entries must be objects")
        records.append({**item, "_jira_issue": parent})
    return records


async def stream_attachments(
    connector: JiraDataCenter,
    checkpoint: Any,
    mode: str,
) -> AsyncIterator[RawBatch]:
    """Enumerate attachments through the changed-issue window and per-issue detail reads."""
    cursor = time_cursor(checkpoint)
    jql = connector._search_jql(cursor.window_start() if mode == "incremental" else None)
    async for issue_page, _result in connector._search(jql, "id,key"):
        for issue in issue_page:
            parent = {"id": jira.required_str(issue, "id"), "key": jira.required_str(issue, "key")}
            detail = await connector._get_object(
                connector._issue_path(parent["id"]),
                {"fields": "attachment"},
            )
            records = attachment_records(detail, parent)
            cursor = connector.advance_cursor(cursor, records, ts_of=attachment_ts, id_of=record_id)
            yield RawBatch(records=records, checkpoint=cursor, complete=False)
    if mode == "full":
        yield RawBatch(records=[], checkpoint=cursor, complete=True)


def _optional_string(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise VendorContractError(f"Jira attachment {key} must be a string")
    return value


def _metadata(raw: dict[str, Any], attachment_id: str) -> GetAttachmentOutput:
    size = raw.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise VendorContractError("Jira attachment size must be a non-negative integer")
    author = raw.get("author")
    if author is not None and not isinstance(author, dict):
        raise VendorContractError("Jira attachment author must be an object")
    return GetAttachmentOutput(
        attachment_id=attachment_id,
        filename=jira.required_str(raw, "filename"),
        media_type=_optional_string(raw, "mimeType"),
        size=size,
        created=_optional_string(raw, "created"),
        author=author,
        self_url=_optional_string(raw, "self"),
        content_url=jira.required_str(raw, "content"),
        thumbnail_url=_optional_string(raw, "thumbnail"),
    )


async def get_attachment(connector: JiraDataCenter, args: GetAttachmentArgs) -> GetAttachmentOutput:
    raw = await connector._get_object(f"/rest/api/2/attachment/{seg(args.attachment_id)}")
    return _metadata(raw, args.attachment_id)


def validate_content_url(
    content_url: str,
    base_url: str,
    *,
    allow_plain_http_loopback: bool = False,
) -> str:
    """Resolve a metadata content URL without leaving the configured origin or context path."""
    normalized_base = normalize_base_url(
        base_url,
        allow_plain_http_loopback=allow_plain_http_loopback,
    )
    resolved = resolve_request_url(
        normalized_base,
        content_url,
        extra_hosts=frozenset(),
        allow_plain_http_loopback=allow_plain_http_loopback,
    )
    context_path = urlsplit(normalized_base).path
    if not urlsplit(resolved).path.startswith(context_path):
        raise UnsafeUrl("attachment content URL is outside the configured Jira context path")
    return resolved


def _download_output(
    metadata: GetAttachmentOutput,
    content: bytes,
    max_bytes: int,
) -> DownloadAttachmentOutput:
    if len(content) > max_bytes:
        raise ConfigError(f"attachment content exceeds the {max_bytes} byte limit")
    if len(content) != metadata.size:
        raise VendorContractError(
            f"Jira attachment size mismatch: metadata declares {metadata.size} bytes, "
            f"content carries {len(content)}"
        )
    return DownloadAttachmentOutput(
        attachment_id=metadata.attachment_id,
        filename=metadata.filename,
        media_type=metadata.media_type,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        content_base64=base64.b64encode(content).decode("ascii"),
    )


async def download_attachment(
    connector: JiraDataCenter,
    args: DownloadAttachmentArgs,
) -> DownloadAttachmentOutput:
    cfg = connector._cfg()
    metadata = await get_attachment(connector, GetAttachmentArgs(attachment_id=args.attachment_id))
    if metadata.size > cfg.attachment_max_bytes:
        raise ConfigError(
            f"attachment size {metadata.size} exceeds the {cfg.attachment_max_bytes} byte limit"
        )
    content_url = validate_content_url(
        metadata.content_url,
        cfg.base_url,
        allow_plain_http_loopback=cfg.allow_plain_http_loopback,
    )
    content = await connector.http.stream_download(
        "GET",
        content_url,
        max_bytes=cfg.attachment_max_bytes,
    )
    return _download_output(metadata, content, cfg.attachment_max_bytes)


def map_attachment(raw: dict[str, Any], ctx: MapContext) -> SourceRecord:
    return jira.map_attachment(raw, ctx)
