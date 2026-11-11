"""Live Archer acceptance: session auth, metadata, content reads, gated writes.

Requires ICUHUB_ACC=1 and ICUHUB_ACC_ARCHER pointing to a JSON file:
{"config": {... ArcherConfig with record_types for the sandbox ...},
 "secrets": {"<ref>": "<password>"},
 "params": {"level_id": 401, "content_id": 1001, "attachment_id": 77,
            "write_record_type": "risks", "correlation_value": "ACC-1",
            "data_feed_guid": "...", "delete_content_id": 1002,
            "delete_level_id": 401},
 "allow_writes": false}
"""

from __future__ import annotations

import asyncio

import httpx2

from icuhub.connectors.archer import Archer
from icuhub.connectors.archer.models import (
    AttachmentRef,
    ContentRef,
    CreateFindingOrExceptionInput,
    DeleteContentInput,
    EmptyInput,
    ExecuteDataFeedInput,
    LevelRef,
    SearchContentArgs,
    UpdateFindingOrExceptionInput,
)
from icuhub.kit.testing import make_connector

ACCEPTANCE_KIND = "archer"


def _connector(acceptance) -> Archer:
    return make_connector(Archer, acceptance.config, httpx2.AsyncHTTPTransport(), acceptance.secrets)  # type: ignore[return-value]


def test_health_version_and_metadata(acceptance) -> None:
    connector = _connector(acceptance)
    report = asyncio.run(connector.check())
    acceptance.record("health", report.status in ("healthy", "degraded"), report.status,
                      vendor_version=report.vendor_version)
    apps = asyncio.run(connector.list_applications(EmptyInput()))
    acceptance.record("list_applications", True, f"{len(apps.items)} applications")
    level_id = int(acceptance.params["level_id"])
    fields = asyncio.run(connector.list_fields(LevelRef(level_id=level_id)))
    acceptance.record("list_fields", len(fields.items) > 0, f"{len(fields.items)} fields")


def test_content_reads(acceptance) -> None:
    connector = _connector(acceptance)
    level_id = int(acceptance.params["level_id"])
    found = asyncio.run(connector.search_content(SearchContentArgs(level_id=level_id, page_size=1)))
    acceptance.record("search_content", True, f"{len(found.records)} records")
    content_id = int(acceptance.params["content_id"])
    content = asyncio.run(connector.get_content(ContentRef(content_id=content_id)))
    acceptance.record("get_content", content.content.content_id == content_id,
                      f"version {content.content.version}")
    history = asyncio.run(connector.get_history(ContentRef(content_id=content_id)))
    acceptance.record("get_history", True, f"{len(history.entries)} entries")
    attachment_id = acceptance.params.get("attachment_id")
    if attachment_id is not None:
        attachment = asyncio.run(connector.get_attachment(AttachmentRef(attachment_id=int(attachment_id))))
        acceptance.record("get_attachment", attachment.size_bytes > 0, f"{attachment.size_bytes} bytes")
    feeds = asyncio.run(connector.get_data_feed_history(EmptyInput()))
    acceptance.record("get_data_feed_history", True, f"{len(feeds.runs)} runs")


def test_write_finding_or_exception(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    record_type = str(acceptance.params["write_record_type"])
    correlation = str(acceptance.params["correlation_value"])
    created = asyncio.run(
        connector.create_finding_or_exception(
            CreateFindingOrExceptionInput(
                record_type=record_type,
                correlation_value=correlation,
                field_values={"Title": correlation},
            )
        )
    )
    outcome = asyncio.run(connector.create_finding_or_exception.apply(created, None))
    acceptance.record("create_finding_or_exception", outcome.status in ("succeeded", "no_op"), outcome.status)
    assert outcome.status in ("succeeded", "no_op")
    content_id = int(outcome.vendor_ref or outcome.result.get("content_id"))
    content = asyncio.run(connector.get_content(ContentRef(content_id=content_id)))
    version = int(content.content.version or 0)
    plan = asyncio.run(
        connector.update_finding_or_exception(
            UpdateFindingOrExceptionInput(
                record_type=record_type,
                content_id=content_id,
                expected_version=version,
                field_values={"Title": f"{correlation}-updated"},
            )
        )
    )
    updated = asyncio.run(connector.update_finding_or_exception.apply(plan, None))
    acceptance.record("update_finding_or_exception", updated.status in ("succeeded", "no_op"), updated.status)


def test_execute_data_feed(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    guid = str(acceptance.params["data_feed_guid"])
    probe = ExecuteDataFeedInput(data_feed_guid=guid, approved_plan_hash="pending")
    plan = asyncio.run(connector.execute_data_feed(probe))
    args = ExecuteDataFeedInput(data_feed_guid=guid, approved_plan_hash=plan.plan_hash)
    outcome = asyncio.run(connector.execute_data_feed.apply(plan, args))
    acceptance.record("execute_data_feed", outcome.status in ("accepted_async", "succeeded"), outcome.status)


def test_delete_content(acceptance) -> None:
    acceptance.require_writes()
    connector = _connector(acceptance)
    content_id = int(acceptance.params["delete_content_id"])
    level_id = int(acceptance.params["delete_level_id"])
    content = asyncio.run(connector.get_content(ContentRef(content_id=content_id)))
    version = int(content.content.version or 0)
    probe = DeleteContentInput(
        content_id=content_id, level_id=level_id, expected_version=version, approved_plan_hash="pending"
    )
    plan = asyncio.run(connector.delete_content(probe))
    args = DeleteContentInput(
        content_id=content_id, level_id=level_id, expected_version=version, approved_plan_hash=plan.plan_hash
    )
    outcome = asyncio.run(connector.delete_content.apply(plan, args))
    acceptance.record("delete_content", outcome.status == "succeeded", outcome.status)
