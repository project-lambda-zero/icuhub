"""Invicti Enterprise stream, cursor, and per-target behavior."""

from __future__ import annotations

import asyncio
import json
from copy import deepcopy

from icuhub.connectors.invicti_enterprise.connector import _parse_time
from icuhub.kit.cursors import TimeIdCursor
from icuhub.kit.testing import collect_stream, map_all

from .conftest import enterprise_connector, load_fixture, target_for_scan


def test_issue_full_sync_pages_and_closes_complete_snapshot() -> None:
    fixture = load_fixture("issues.json")
    first = deepcopy(fixture["List"][0])
    second = deepcopy(first)
    second["Id"] = "6dc7a92f-94ab-4f7c-b60f-000000000302"

    def issues(request):
        if request.url.params.get("page") == "1":
            return {"status": 200, "json": {**fixture, "List": [first], "HasNextPage": True, "IsLastPage": False}}
        return {"status": 200, "json": {**fixture, "List": [second], "HasNextPage": False, "IsLastPage": True}}

    connector = enterprise_connector({("GET", "/api/1.0/issues/allissues"): issues})
    batches = collect_stream(connector, "issues", mode="full")

    assert len(batches) == 3
    assert batches[-1].complete is True
    assert batches[-1].checkpoint.ts.isoformat() == "2026-11-01T11:00:00+00:00"
    findings = map_all(connector, "issues", [record for batch in batches for record in batch.records])
    assert len(findings) == 2
    for finding in findings:
        finding.to_ocsf()


def test_timestamp_tie_overflow_replays_instead_of_dropping_ids() -> None:
    connector = enterprise_connector({}, max_tie_ids=100)
    raw = load_fixture("issues.json")["List"][0]
    records = []
    for index in range(101):
        item = deepcopy(raw)
        item["Id"] = f"issue-{index}"
        records.append(item)
    cursor = connector._advance(
        TimeIdCursor(ts=None),
        records,
        ts_of=lambda item: _parse_time(item["LastSeenDate"], "LastSeenDate"),
        id_of=lambda item: item["Id"],
    )
    assert cursor.ts is not None
    assert cursor.last_ids_at_ts == []


def test_scan_sync_discovery_and_non_finding_mapping() -> None:
    scans = load_fixture("scans.json")
    connector = enterprise_connector({("GET", "/api/1.0/scans/list"): {"status": 200, "json": scans}})
    batches = collect_stream(connector, "scans", mode="full")
    assert batches[-1].complete is True
    record = map_all(connector, "scans", batches[0].records)[0]
    assert record.record_type == "invicti_scan"
    assert record.uid == scans["List"][0]["Id"]

    async def discover():
        return [target async for target in connector.discover()]

    targets = asyncio.run(discover())
    assert len(targets) == 1
    assert targets[0].kind == "invicti_scan"
    assert targets[0].source_uid == scans["List"][0]["Id"]


def test_scan_result_snapshot_maps_with_scan_identity() -> None:
    target = target_for_scan()
    results = load_fixture("scan_results.json")
    connector = enterprise_connector(
        {("GET", f"/api/1.0/scans/result/{target.source_uid}"): {"status": 200, "text": json.dumps(results)}}
    )
    batches = collect_stream(connector, "scan_results", target=target, mode="full")
    assert len(batches) == 1
    assert batches[0].complete is True
    assert batches[0].checkpoint.snapshot_id == f"scan-result:{target.source_uid}"
    finding = map_all(connector, "scan_results", batches[0].records)[0]
    assert finding.metadata.uid == target.source_uid
    assert finding.unmapped["invicti"]["scan_id"] == target.source_uid
    finding.to_ocsf()


def test_report_stream_and_replay_use_exact_report_snapshot() -> None:
    target = target_for_scan()
    report = (load_fixture("report.json"))
    connector = enterprise_connector(
        {("GET", "/api/1.0/scans/report"): {"status": 200, "text": json.dumps(report)}}
    )
    first = collect_stream(connector, "report_issues", target=target, mode="full")
    replay = collect_stream(connector, "report_issues", target=target, mode="replay")
    assert first[0].complete is True
    assert first[0].checkpoint.snapshot_id == replay[0].checkpoint.snapshot_id
    finding = map_all(connector, "report_issues", first[0].records)[0]
    assert finding.unmapped["invicti"]["report"]["snapshot_id"] == first[0].checkpoint.snapshot_id
    finding.to_ocsf()
