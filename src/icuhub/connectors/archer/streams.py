"""Archer streams: time_id record streams and snapshot streams.

Time-id streams page SOAP ExecuteSearch over the configured record-type mapping
and checkpoint with a TimeIdCursor (overlap replay plus id dedupe). Snapshot
streams (attachments, history, data_feed_runs) are full-only and checkpoint with
a SnapshotCursor. Record types that are not configured are a configuration
error, never an empty-success stream.
"""

import hashlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, cast

from icuhub.kit import ConfigError, RawBatch, SnapshotCursor, TimeIdCursor

from .models import ArcherRecordTypeMap

__all__ = ["STREAM_SPECS", "run_stream"]

STREAM_SPECS: dict[str, dict[str, Any]] = {
    "vulnerability_scan_results": {"cursor": "time_id", "ocsf_class": 2002, "modes": ("incremental", "full")},
    "assessment_findings": {"cursor": "time_id", "ocsf_class": 2003, "modes": ("incremental", "full")},
    "risks": {"cursor": "time_id", "ocsf_class": None, "modes": ("incremental", "full")},
    "exception_requests": {"cursor": "time_id", "ocsf_class": None, "modes": ("incremental", "full")},
    "remediation_plans": {"cursor": "time_id", "ocsf_class": None, "modes": ("incremental", "full")},
    "applications_devices": {"cursor": "time_id", "ocsf_class": None, "modes": ("incremental", "full")},
    "vulnerability_library": {"cursor": "time_id", "ocsf_class": None, "modes": ("incremental", "full")},
    "attachments": {"cursor": "snapshot", "ocsf_class": None, "modes": ("full",)},
    "history": {"cursor": "snapshot", "ocsf_class": None, "modes": ("full",)},
    "data_feed_runs": {"cursor": "snapshot", "ocsf_class": None, "modes": ("full",)},
}


def _mapping(connector, name: str) -> ArcherRecordTypeMap:
    mapping = connector.config.record_types.get(name)
    if mapping is None:
        raise ConfigError(f"archer record_types[{name!r}] is required for the {name} stream")
    return mapping


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, list):
        value = value[0] if value else None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _snapshot_cursor(connector, name: str) -> SnapshotCursor:
    started_at = connector.ctx.clock()
    digest = hashlib.sha256(f"{connector.ctx.connection_id}:{name}:{started_at.isoformat()}".encode()).hexdigest()
    return SnapshotCursor(snapshot_id=digest[:32], started_at=started_at)


async def run_stream(connector, name: str, target, checkpoint, mode) -> AsyncIterator[RawBatch]:
    spec = STREAM_SPECS[name]
    if spec["cursor"] == "time_id":
        async for batch in _time_id_stream(connector, name, checkpoint, mode):
            yield batch
    elif name == "data_feed_runs":
        runs = await connector.api.data_feed_history()
        records = [
            {"record_type": name, "run": run, "run_index": index}
            for index, run in enumerate(runs)
        ]
        yield RawBatch(records=records, checkpoint=_snapshot_cursor(connector, name), complete=True)
    else:
        async for batch in _snapshot_records(connector, name):
            yield batch


async def _time_id_stream(connector, name: str, checkpoint, mode: str) -> AsyncIterator[RawBatch]:
    cfg = connector.config
    mapping = _mapping(connector, name)
    fields = await connector.api.fields_for_level(mapping.level_id)
    by_name = {str(f.get("Name")): int(f["Id"]) for f in fields if f.get("Id") is not None}
    display = dict(mapping.field_ids) or by_name
    time_name = mapping.time_field or "LastUpdated"  # [UNVERIFIED] default time field name
    time_field_id = display.get(time_name) or by_name.get(time_name)
    if time_field_id is None:
        raise ConfigError(f"archer level {mapping.level_id} has no time field {time_name!r}")
    cursor = checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)
    since = cursor.window_start() if mode == "incremental" else None

    for page in range(1, cfg.max_pages + 1):
        records = await connector.api.search_records(
            level_id=mapping.level_id,
            application_id=mapping.application_id,
            page_number=page,
            page_size=cfg.page_size,
            display_fields=display,
            modified_since=since,
            time_field_id=time_field_id,
        )
        rows: list[tuple[dict[str, Any], datetime | None]] = []
        for record in records:
            fields_map = record.get("fields") or {}
            ts = _parse_time(fields_map.get(time_name))
            if ts is not None and cursor.is_duplicate(ts, str(record["content_id"])):
                continue
            raw = {
                "content_id": int(record["content_id"]),
                "level_id": mapping.level_id,
                "application_id": mapping.application_id,
                "record_type": name,
                "fields": fields_map,
            }
            rows.append((raw, ts))
        cursor = cursor.advance(
            [row for row in rows if row[1] is not None],
            ts_of=lambda row: cast(datetime, row[1]),
            id_of=lambda row: str(row[0]["content_id"]),
        )
        complete = len(records) < cfg.page_size or page == cfg.max_pages
        yield RawBatch(records=[row[0] for row in rows], checkpoint=cursor, complete=complete)
        if complete:
            return


async def _snapshot_records(connector, name: str) -> AsyncIterator[RawBatch]:
    cfg = connector.config
    mapping = _mapping(connector, name)
    cursor = _snapshot_cursor(connector, name)
    for page in range(1, cfg.max_pages + 1):
        records = await connector.api.search_records(
            level_id=mapping.level_id,
            application_id=mapping.application_id,
            page_number=page,
            page_size=cfg.page_size,
            display_fields=dict(mapping.field_ids) or None,
        )
        out: list[dict[str, Any]] = []
        for record in records:
            content_id = int(record["content_id"])
            if name == "history":
                entries = await connector.api.history(content_id)
                out.append({"record_type": name, "content_id": content_id, "entries": entries})
                continue
            content = await connector.api.content(content_id)
            for fid, entry in (content.get("FieldContents") or {}).items():
                if not isinstance(entry, dict) or int(entry.get("Type") or 0) != 11:
                    continue
                value = entry.get("Value")
                attachments = value if isinstance(value, list) else ([value] if value else [])
                for item in attachments:
                    if not isinstance(item, dict) or item.get("Id") is None:
                        continue
                    out.append(
                        {
                            "record_type": name,
                            "content_id": content_id,
                            "attachment_id": int(item["Id"]),
                            "filename": item.get("Name"),
                            "field_id": str(fid),
                            "fields": {},
                        }
                    )
        complete = len(records) < cfg.page_size or page == cfg.max_pages
        yield RawBatch(records=out, checkpoint=cursor, complete=complete)
        if complete:
            return
