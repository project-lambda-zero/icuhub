"""Archer record, evidence, history, and data-feed streams.

Time-id checkpoints advance only after a complete, untruncated traversal whose requested
fields are readable. Targeted reads fetch one configured parent or feed and never authorize
absence closure. Missing record-type mappings and data-feed targets are configuration errors,
never empty successful streams.
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
    "attachments": {"cursor": "snapshot", "ocsf_class": None, "modes": ("full", "targeted")},
    "history": {"cursor": "snapshot", "ocsf_class": None, "modes": ("full", "targeted")},
    "data_feed_runs": {"cursor": "snapshot", "ocsf_class": None, "modes": ("full", "targeted")},
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


def _target_attribute(target: Any, *names: str) -> str | None:
    attributes = getattr(target, "attributes", None) or getattr(target, "attributes_json", None) or {}
    for name in names:
        value = attributes.get(name)
        if value is not None and str(value).strip():
            return str(value)
    source_uid = getattr(target, "source_uid", None)
    if source_uid is not None and str(source_uid).strip():
        return str(source_uid)
    return None


def _target_content_id(target: Any) -> int:
    value = _target_attribute(target, "content_id", "contentId")
    if value is None:
        raise ConfigError("targeted Archer content reads require target.attributes.content_id")
    try:
        content_id = int(value)
    except ValueError as exc:
        raise ConfigError("Archer target content_id must be an integer") from exc
    if content_id < 1:
        raise ConfigError("Archer target content_id must be positive")
    return content_id


def _target_feed_guid(target: Any) -> str:
    value = _target_attribute(target, "data_feed_guid", "feed_guid", "Guid")
    if value is None:
        raise ConfigError("targeted Archer data-feed reads require target.attributes.data_feed_guid")
    return value


def _attachment_records(content: dict[str, Any], content_id: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for field_id, entry in (content.get("FieldContents") or {}).items():
        if not isinstance(entry, dict) or int(entry.get("Type") or 0) != 11:
            continue
        value = entry.get("Value")
        attachments = value if isinstance(value, list) else ([value] if value else [])
        for item in attachments:
            if not isinstance(item, dict) or item.get("Id") is None:
                continue
            records.append(
                {
                    "record_type": "attachments",
                    "content_id": content_id,
                    "attachment_id": int(item["Id"]),
                    "filename": item.get("Name"),
                    "field_id": str(field_id),
                    "fields": {},
                }
            )
    return records


def _data_feed_records(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"record_type": "data_feed_runs", "run": run, "run_index": index}
        for index, run in enumerate(runs)
    ]


async def run_stream(connector, name: str, target, checkpoint, mode) -> AsyncIterator[RawBatch]:
    spec = STREAM_SPECS[name]
    if mode == "targeted":
        if name == "data_feed_runs":
            runs = await connector.api.data_feed_history(_target_feed_guid(target))
            records = _data_feed_records(runs)
        elif name == "history":
            content_id = _target_content_id(target)
            entries = await connector.api.history(content_id)
            records = [{"record_type": name, "content_id": content_id, "entries": entries}]
        elif name == "attachments":
            content_id = _target_content_id(target)
            records = _attachment_records(await connector.api.content(content_id), content_id)
        else:
            raise ConfigError(f"Archer stream {name!r} does not support targeted reads")
        yield RawBatch(records=records, checkpoint=_snapshot_cursor(connector, name), complete=True)
        return
    if spec["cursor"] == "time_id":
        async for batch in _time_id_stream(connector, name, checkpoint, mode):
            yield batch
    elif name == "data_feed_runs":
        guids = list(connector.config.data_feed_guids)
        if not guids:
            raise ConfigError("archer data_feed_guids must name every feed in a full data_feed_runs snapshot")
        records: list[dict[str, Any]] = []
        for guid in guids:
            records.extend(_data_feed_records(await connector.api.data_feed_history(guid)))
        for index, record in enumerate(records):
            record["run_index"] = index
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
    committed = checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)
    discovered = committed
    since = committed.window_start() if mode == "incremental" else None

    for page in range(1, cfg.max_pages + 1):
        records = await connector.api.search_records(
            level_id=mapping.level_id,
            application_id=mapping.application_id,
            page_number=page,
            page_size=cfg.page_size,
            display_fields=display,
            modified_since=since,
            time_field_id=time_field_id,
            sort_field_id=time_field_id,
        )
        rows: list[tuple[dict[str, Any], datetime | None]] = []
        omitted_fields = False
        for record in records:
            fields_map = record.get("fields") or {}
            omitted_fields = omitted_fields or bool(record.get("omitted_fields"))
            ts = _parse_time(fields_map.get(time_name))
            version = record.get("version")
            identity = f"{record['content_id']}:{version if version is not None else 'unknown'}"
            if ts is not None and discovered.is_duplicate(ts, identity):
                continue
            raw = {
                "content_id": int(record["content_id"]),
                "version": int(version) if version is not None else None,
                "level_id": mapping.level_id,
                "application_id": mapping.application_id,
                "record_type": name,
                "fields": fields_map,
                "omitted_fields": list(record.get("omitted_fields") or []),
            }
            rows.append((raw, ts))
        discovered = discovered.advance(
            [row for row in rows if row[1] is not None],
            ts_of=lambda row: cast(datetime, row[1]),
            id_of=lambda row: f"{row[0]['content_id']}:{row[0]['version'] if row[0]['version'] is not None else 'unknown'}",
        )
        short_page = len(records) < cfg.page_size
        complete = short_page and not omitted_fields
        yield RawBatch(
            records=[row[0] for row in rows],
            checkpoint=discovered if complete else committed,
            complete=complete,
        )
        if complete or short_page or page == cfg.max_pages:
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
        omitted_fields = False
        for record in records:
            omitted_fields = omitted_fields or bool(record.get("omitted_fields"))
            content_id = int(record["content_id"])
            if name == "history":
                entries = await connector.api.history(content_id)
                out.append({"record_type": name, "content_id": content_id, "entries": entries})
                continue
            content = await connector.api.content(content_id)
            out.extend(_attachment_records(content, content_id))
        short_page = len(records) < cfg.page_size
        complete = short_page and not omitted_fields
        yield RawBatch(records=out, checkpoint=cursor, complete=complete)
        if complete or short_page or page == cfg.max_pages:
            return
