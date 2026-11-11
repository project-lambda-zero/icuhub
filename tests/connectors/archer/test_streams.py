"""Archer stream tests: paging, cursors, dedupe, snapshots, configuration errors."""

import json
from pathlib import Path

import pytest

from icuhub.kit import ConfigError, SnapshotCursor, TimeIdCursor
from icuhub.kit.testing import collect_stream

from .conftest import RouteTransport, make_archer

CLIENT = Path(__file__).parents[2] / "fixtures" / "archer" / "client"
STREAMS = Path(__file__).parents[2] / "fixtures" / "archer" / "streams"
OPS = Path(__file__).parents[2] / "fixtures" / "archer" / "operations"
LOGIN = ("POST", "/platformapi/core/security/login")
SEARCH = ("POST", "/ws/search.asmx")
FIELDS = ("POST", "/platformapi/core/system/fielddefinition/level/401")

RISK_MAP = {
    "application_id": 301,
    "level_id": 401,
    "field_ids": {"Title": 5001, "LastUpdated": 5002},
    "correlation_field": "Title",
    "time_field": "LastUpdated",
}


def xml(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def routes_for(search_xml: str):
    return {
        LOGIN: {"json": json.loads((CLIENT / "login.json").read_text(encoding="utf-8"))},
        FIELDS: {"json": json.loads((CLIENT / "fields_level.json").read_text(encoding="utf-8"))},
        SEARCH: {"text": search_xml},
    }


def risk_connector(routes, **overrides):
    record_types = overrides.pop("record_types", {"risks": RISK_MAP})
    return make_archer(
        RouteTransport(routes),
        config_overrides={"record_types": record_types, **overrides},
    )


def test_missing_record_type_mapping_is_config_error():
    connector = risk_connector(routes_for(xml(STREAMS / "soap_search_one.xml")), record_types={})
    with pytest.raises(ConfigError):
        collect_stream(connector, "risks")


def test_unresolved_time_field_is_config_error():
    bad = dict(RISK_MAP, time_field="No Such Time")
    connector = risk_connector(routes_for(xml(STREAMS / "soap_search_one.xml")), record_types={"risks": bad})
    with pytest.raises(ConfigError):
        collect_stream(connector, "risks")


def test_time_id_stream_records_and_checkpoint():
    connector = risk_connector(routes_for(xml(CLIENT / "soap_search.xml")))
    batches = collect_stream(connector, "risks")
    assert len(batches) == 1
    batch = batches[0]
    assert batch.complete is True
    assert [r["content_id"] for r in batch.records] == [1001, 1002]
    raw = batch.records[0]
    assert raw["record_type"] == "risks"
    assert raw["application_id"] == 301 and raw["level_id"] == 401
    assert raw["fields"]["Title"] == "Risk A"
    assert isinstance(batch.checkpoint, TimeIdCursor)
    assert batch.checkpoint.ts is not None
    assert batch.checkpoint.ts.isoformat() == "2026-01-03T03:04:05+00:00"
    assert sorted(batch.checkpoint.last_ids_at_ts) == ["1002:unknown"]


def test_empty_stream_yields_one_complete_empty_batch():
    connector = risk_connector(routes_for(xml(STREAMS / "soap_search_empty.xml")))
    batches = collect_stream(connector, "risks")
    assert len(batches) == 1
    assert batches[0].records == []
    assert batches[0].complete is True


def test_pagination_stops_on_short_page():
    pages = []

    def search(request):
        body = request.content.decode("utf-8")
        pages.append(body)
        if "<PageNumber>1</PageNumber>" in body:
            return {"text": xml(CLIENT / "soap_search.xml")}
        return {"text": xml(STREAMS / "soap_search_empty.xml")}

    routes = routes_for("")
    routes[SEARCH] = search
    connector = risk_connector(routes, page_size=2)
    batches = collect_stream(connector, "risks", mode="full")
    assert len(batches) == 2
    assert batches[0].complete is False and len(batches[0].records) == 2
    assert batches[1].complete is True and batches[1].records == []
    assert len(pages) == 2
    assert "DateComparisonFilterCondition" not in pages[0]


def test_incremental_overlap_dedupes_committed_ids():
    seen = []

    def search(request):
        seen.append(request.content.decode("utf-8"))
        return {"text": xml(STREAMS / "soap_search_same_ts.xml")}

    routes = routes_for("")
    routes[SEARCH] = search
    connector = risk_connector(routes)
    first = collect_stream(connector, "risks", mode="full")
    checkpoint = first[-1].checkpoint
    assert isinstance(checkpoint, TimeIdCursor)
    assert sorted(checkpoint.last_ids_at_ts) == ["1001:unknown", "1002:unknown"]
    second = collect_stream(connector, "risks", checkpoint=checkpoint, mode="incremental")
    assert second[0].records == []
    assert "DateComparisonFilterCondition" in seen[-1]


def test_malformed_timestamp_keeps_record_without_advancing_cursor():
    connector = risk_connector(routes_for(xml(STREAMS / "soap_search_bad_time.xml")))
    batches = collect_stream(connector, "risks")
    assert [r["content_id"] for r in batches[0].records] == [1001]
    checkpoint = batches[0].checkpoint
    assert isinstance(checkpoint, TimeIdCursor)
    assert checkpoint.ts is None


def test_attachments_snapshot_expands_attachment_fields_without_download():
    routes = routes_for(xml(STREAMS / "soap_search_one.xml"))
    routes[("POST", "/platformapi/core/content/contentid")] = {
        "json": json.loads((STREAMS / "content_attachments.json").read_text(encoding="utf-8"))
    }
    connector = risk_connector(routes, record_types={"attachments": RISK_MAP})
    batches = collect_stream(connector, "attachments", mode="full")
    records = batches[0].records
    assert [(r["attachment_id"], r["filename"]) for r in records] == [(77, "evidence.pdf"), (78, "notes.txt")]
    assert all(r["content_id"] == 1001 for r in records)
    assert isinstance(batches[0].checkpoint, SnapshotCursor)
    assert batches[0].complete is True


def test_history_snapshot_collects_entries_per_record():
    routes = routes_for(xml(STREAMS / "soap_search_one.xml"))
    routes[("POST", "/platformapi/core/content/history/1001")] = {
        "json": json.loads((OPS / "history.json").read_text(encoding="utf-8"))
    }
    connector = risk_connector(routes, record_types={"history": RISK_MAP})
    batches = collect_stream(connector, "history", mode="full")
    assert batches[0].records[0]["content_id"] == 1001
    assert batches[0].records[0]["entries"][0]["Version"] == 6


def test_data_feed_runs_snapshot():
    routes = {
        LOGIN: {"json": json.loads((CLIENT / "login.json").read_text(encoding="utf-8"))},
        ("POST", "/platformapi/core/datafeed/history"): {
            "json": json.loads((OPS / "data_feed_history.json").read_text(encoding="utf-8"))
        },
    }
    connector = risk_connector(routes, data_feed_guids=["df-1"])
    batches = collect_stream(connector, "data_feed_runs", mode="full")
    assert len(batches) == 1
    assert batches[0].records[0]["run"]["Guid"] == "df-1"
    assert batches[0].complete is True
