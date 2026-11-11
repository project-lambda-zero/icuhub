"""Offline tests for Jira Data Center attachment inventory and content reads."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

import httpx2
import pytest

from icuhub.connectors.jira_dc import JiraDataCenter
from icuhub.connectors.jira_dc.attachments import (
    DownloadAttachmentArgs,
    GetAttachmentArgs,
)
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.errors import BudgetExhausted, ConfigError, UnsafeUrl, VendorContractError
from icuhub.kit.testing import RouteTransport, collect_stream, make_connector, map_all
from icuhub.kit.types import SourceRecord

BASE = "https://jira.example.test/jira"
ORIGIN = "https://jira.example.test"
PAT_REF = "jira-pat"
SECRETS = {PAT_REF: b"synthetic-pat"}
ATTACHMENT_ID = "90001"
CONTENT_PATH = "/jira/secure/attachment/90001/evidence.txt"
CONTENT_URL = ORIGIN + CONTENT_PATH
METADATA_ROUTE = ("GET", "/jira/rest/api/2/attachment/90001")


def _config(**extra: Any) -> dict[str, Any]:
    return {"base_url": BASE, "personal_access_token": {"ref": PAT_REF}, **extra}


def _connector(routes: dict[tuple[str, str], Any], **config_extra: Any) -> JiraDataCenter:
    return cast(
        JiraDataCenter,
        make_connector(JiraDataCenter, _config(**config_extra), RouteTransport(routes), SECRETS),
    )


def _recording(payload: Any, seen: list[httpx2.Request]) -> Callable[[httpx2.Request], dict[str, Any]]:
    def handler(request: httpx2.Request) -> dict[str, Any]:
        seen.append(request)
        return {"status": 200, "json": payload}

    return handler


def _metadata(*, size: int = 3, content_url: str = CONTENT_URL) -> dict[str, Any]:
    return {
        "id": ATTACHMENT_ID,
        "self": ORIGIN + "/jira/rest/api/2/attachment/90001",
        "filename": "evidence.txt",
        "author": {"name": "researcher", "displayName": "Researcher"},
        "created": "2026-11-09T10:59:00.000+00:00",
        "size": size,
        "mimeType": "text/plain",
        "content": content_url,
    }


def _search() -> dict[str, Any]:
    return {"issues": [{"id": "10001", "key": "PROJ-1"}]}


def _issue_detail() -> dict[str, Any]:
    return {"fields": {"attachment": [_metadata()]}}


def test_attachments_incremental_uses_window_and_per_issue_detail_reads() -> None:
    search_seen: list[httpx2.Request] = []
    detail_seen: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", "/jira/rest/api/2/search"): _recording(_search(), search_seen),
            ("GET", "/jira/rest/api/2/issue/10001"): _recording(_issue_detail(), detail_seen),
        }
    )
    checkpoint = TimeIdCursor(ts=datetime(2026, 11, 9, 10, 0, tzinfo=UTC), overlap_s=300)

    batches = collect_stream(connector, "attachments", checkpoint=checkpoint, mode="incremental")

    records = [record for batch in batches for record in batch.records]
    assert [record["id"] for record in records] == [ATTACHMENT_ID]
    assert records[0]["_jira_issue"] == {"id": "10001", "key": "PROJ-1"}
    assert search_seen[0].url.params["fields"] == "id,key"
    assert 'updated >= "2026-11-09 09:55"' in search_seen[0].url.params["jql"]
    assert detail_seen[0].url.params["fields"] == "attachment"
    assert isinstance(batches[-1].checkpoint, TimeIdCursor)
    assert batches[-1].checkpoint.ts == datetime(2026, 11, 9, 10, 59, tzinfo=UTC)


def test_attachments_full_mode_closes_snapshot_without_incremental_window() -> None:
    search_seen: list[httpx2.Request] = []
    connector = _connector(
        {
            ("GET", "/jira/rest/api/2/search"): _recording(_search(), search_seen),
            ("GET", "/jira/rest/api/2/issue/10001"): {"status": 200, "json": _issue_detail()},
        }
    )
    checkpoint = TimeIdCursor(ts=datetime(2026, 11, 9, 11, 0, tzinfo=UTC))

    batches = collect_stream(connector, "attachments", checkpoint=checkpoint, mode="full")

    assert "updated >=" not in search_seen[0].url.params["jql"]
    assert len([record for batch in batches for record in batch.records]) == 1
    assert batches[-1].records == []
    assert batches[-1].complete is True


def test_attachment_mapper_produces_evidence_record_with_parent_identity() -> None:
    connector = _connector({})
    raw = {**_metadata(), "_jira_issue": {"id": "10001", "key": "PROJ-1"}}

    (record,) = map_all(connector, "attachments", [raw])

    assert isinstance(record, SourceRecord)
    assert record.record_type == "evidence"
    assert record.uid == "jira_attachment:test-connection/10001/90001"
    assert record.data["issue_key"] == "PROJ-1"


def test_get_attachment_returns_typed_metadata() -> None:
    connector = _connector({METADATA_ROUTE: {"status": 200, "json": _metadata()}})

    output = asyncio.run(connector.get_attachment(GetAttachmentArgs(attachment_id=ATTACHMENT_ID)))

    assert output.attachment_id == ATTACHMENT_ID
    assert output.filename == "evidence.txt"
    assert output.media_type == "text/plain"
    assert output.size == 3
    assert output.content_url == CONTENT_URL


def test_download_attachment_returns_base64_and_correct_sha256() -> None:
    payload = b"synthetic evidence\x00\xff"
    connector = _connector(
        {
            METADATA_ROUTE: {"status": 200, "json": _metadata(size=len(payload))},
            ("GET", CONTENT_PATH): lambda request: httpx2.Response(200, content=payload),
        }
    )

    output = asyncio.run(connector.download_attachment(DownloadAttachmentArgs(attachment_id=ATTACHMENT_ID)))

    assert output.size == len(payload)
    assert base64.b64decode(output.content_base64) == payload
    assert output.sha256 == hashlib.sha256(payload).hexdigest()


def test_download_attachment_refuses_metadata_size_above_configured_cap() -> None:
    connector = _connector(
        {METADATA_ROUTE: {"status": 200, "json": _metadata(size=5)}},
        attachment_max_bytes=4,
    )

    with pytest.raises(ConfigError, match="exceeds the 4 byte limit"):
        asyncio.run(connector.download_attachment(DownloadAttachmentArgs(attachment_id=ATTACHMENT_ID)))


def test_download_attachment_refuses_oversize_content_length_before_reading() -> None:
    connector = _connector(
        {
            METADATA_ROUTE: {"status": 200, "json": _metadata(size=1)},
            ("GET", CONTENT_PATH): lambda request: httpx2.Response(
                200,
                headers={"Content-Length": "5"},
                content=b"12345",
            ),
        },
        attachment_max_bytes=4,
    )

    with pytest.raises(BudgetExhausted, match="declares 5 bytes"):
        asyncio.run(connector.download_attachment(DownloadAttachmentArgs(attachment_id=ATTACHMENT_ID)))


def test_download_attachment_refuses_body_that_exceeds_cap_while_reading() -> None:
    connector = _connector(
        {
            METADATA_ROUTE: {"status": 200, "json": _metadata(size=4)},
            ("GET", CONTENT_PATH): lambda request: httpx2.Response(
                200,
                headers={"Content-Length": "4"},
                content=b"12345",
            ),
        },
        attachment_max_bytes=4,
    )

    with pytest.raises(BudgetExhausted, match="exceeded the 4 byte cap"):
        asyncio.run(connector.download_attachment(DownloadAttachmentArgs(attachment_id=ATTACHMENT_ID)))


def test_download_attachment_refuses_content_size_mismatch() -> None:
    connector = _connector(
        {
            METADATA_ROUTE: {"status": 200, "json": _metadata(size=4)},
            ("GET", CONTENT_PATH): lambda request: httpx2.Response(200, content=b"abc"),
        }
    )

    with pytest.raises(VendorContractError, match="size mismatch"):
        asyncio.run(connector.download_attachment(DownloadAttachmentArgs(attachment_id=ATTACHMENT_ID)))


def test_download_attachment_refuses_cross_origin_content_url() -> None:
    connector = _connector(
        {
            METADATA_ROUTE: {
                "status": 200,
                "json": _metadata(content_url="https://outside.example.test/jira/secure/evidence.txt"),
            }
        }
    )

    with pytest.raises(UnsafeUrl, match="origin does not match"):
        asyncio.run(connector.download_attachment(DownloadAttachmentArgs(attachment_id=ATTACHMENT_ID)))


def test_download_attachment_refuses_content_outside_configured_context_path() -> None:
    connector = _connector(
        {
            METADATA_ROUTE: {
                "status": 200,
                "json": _metadata(content_url=ORIGIN + "/secure/attachment/90001/evidence.txt"),
            }
        }
    )

    with pytest.raises(UnsafeUrl, match="outside the configured Jira context path"):
        asyncio.run(connector.download_attachment(DownloadAttachmentArgs(attachment_id=ATTACHMENT_ID)))
