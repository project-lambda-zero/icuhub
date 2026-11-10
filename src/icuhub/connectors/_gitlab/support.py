"""Shared helpers for GitLab stream fetchers and mappers.

Stream helpers encode the completeness contract: a snapshot authorizes absence closure only when
every page was read, and a time-id cursor advances only across a complete read. Mapper helpers
build scoped uids, source records, and OCSF-validated models. Slice modules import these names
directly; nothing here depends on a slice.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from icuhub.kit.cursors import SnapshotCursor, TimeIdCursor
from icuhub.kit.errors import BudgetExhausted, ConfigError, VendorContractError
from icuhub.kit.mapping import bounded_raw
from icuhub.kit.types import RawBatch, SourceRecord, Target
from icuhub_schemas.ocsf import validate_ocsf

if TYPE_CHECKING:
    from icuhub.connectors._gitlab.connector import GitLabConnectorBase

__all__ = [
    "BATCH_SIZE",
    "Fetch",
    "annotate",
    "checked",
    "data",
    "gather",
    "gather_each",
    "links",
    "numeric_id",
    "required",
    "revision",
    "snapshot_batches",
    "snapshot_cursor",
    "source",
    "time_cursor",
    "time_id_batches",
    "uid",
    "window_query",
]

BATCH_SIZE = 100
Fetch = Callable[[dict[str, Any]], Awaitable[list[dict[str, Any]]]]

# OCSF "Base Event" (class_uid 0): the documented carrier for GitLab objects with no OCSF class.
_NON_OCSF_CLASS_UID = 0


def numeric_id(target: Target | None, kind: str) -> int:
    if target is None or not target.id.isdigit():
        raise ConfigError(f"GitLab {kind} streams require a target whose id is the numeric GitLab {kind} id")
    return int(target.id)


def annotate(records: list[dict[str, Any]], **fields: Any) -> list[dict[str, Any]]:
    return [{**record, **fields} for record in records]


async def gather(
    connector: GitLabConnectorBase, path: str, params: dict[str, str] | None = None
) -> tuple[list[dict[str, Any]], bool]:
    """Return every page read; ``complete`` is False when the page budget stopped the read."""
    return await connector._collect_partial(path, params)


async def gather_each(parents: list[dict[str, Any]], fetch: Fetch) -> tuple[list[dict[str, Any]], bool]:
    records: list[dict[str, Any]] = []
    for parent in parents:
        try:
            records.extend(await fetch(parent))
        except BudgetExhausted:
            return records, False
    return records, True


def snapshot_cursor(connector: GitLabConnectorBase, stream_name: str, scope: str) -> SnapshotCursor:
    started_at = connector.ctx.clock()
    material = f"{connector.ctx.connection_id}\x1f{stream_name}\x1f{scope}\x1f{started_at.isoformat()}"
    return SnapshotCursor(
        snapshot_id=hashlib.sha256(material.encode("utf-8")).hexdigest()[:32],
        started_at=started_at,
        targets_done=[],
    )


async def snapshot_batches(
    connector: GitLabConnectorBase,
    stream_name: str,
    scope: str,
    records: list[dict[str, Any]],
    *,
    complete: bool,
) -> AsyncIterator[RawBatch]:
    cursor = snapshot_cursor(connector, stream_name, scope)
    for offset in range(0, len(records), BATCH_SIZE):
        yield RawBatch(records=records[offset : offset + BATCH_SIZE], checkpoint=cursor, complete=False)
    yield RawBatch(records=[], checkpoint=cursor, complete=complete)


def time_cursor(checkpoint: TimeIdCursor | None) -> TimeIdCursor:
    return checkpoint if isinstance(checkpoint, TimeIdCursor) else TimeIdCursor(ts=None)


def window_query(checkpoint: TimeIdCursor | None, mode: str, param: str) -> dict[str, str]:
    window = time_cursor(checkpoint).window_start() if mode == "incremental" else None
    return {} if window is None else {param: window.isoformat()}


async def time_id_batches(
    records: list[dict[str, Any]],
    checkpoint: TimeIdCursor | None,
    mode: str,
    *,
    complete: bool,
    time_of: Callable[[dict[str, Any]], datetime],
    id_of: Callable[[dict[str, Any]], str],
    durable: Callable[[dict[str, Any]], bool] | None = None,
) -> AsyncIterator[RawBatch]:
    """Yield the in-window records in time order and advance the cursor across the durable prefix.

    ``durable`` marks records that are fully captured (for example, a download that was not truncated).
    A non-durable record is still emitted, as a visible bounded record, so the dropped result is not hidden.
    It does not advance the cursor: the cursor stops at the last durable record before it, the batch is
    incomplete, and the non-durable record is re-read on the next run.
    """
    cursor = time_cursor(checkpoint)
    if not complete:
        # A partial read must not advance the cursor: unseen older records would be skipped forever.
        yield RawBatch(records=[], checkpoint=cursor, complete=False)
        return
    latest: dict[str, tuple[datetime, dict[str, Any]]] = {}
    for raw in records:
        timestamp = time_of(raw)
        record_id = id_of(raw)
        previous = latest.get(record_id)
        if previous is None or timestamp > previous[0]:
            latest[record_id] = (timestamp, raw)
    window = cursor.window_start() if mode == "incremental" else None
    selected: list[tuple[datetime, str, dict[str, Any]]] = []
    visible: list[dict[str, Any]] = []
    stopped = False
    for record_id, (timestamp, raw) in sorted(latest.items(), key=lambda item: (item[1][0], item[0])):
        if window is not None and timestamp < window:
            continue
        if mode == "incremental" and cursor.is_duplicate(timestamp, record_id):
            continue
        if durable is not None and not durable(raw):
            # The first non-durable record is the gap: emit it visibly and read nothing past it.
            visible.append(raw)
            stopped = True
            break
        selected.append((timestamp, record_id, raw))
    cursor = cursor.advance(selected, ts_of=lambda row: row[0], id_of=lambda row: row[1])
    output = [row[2] for row in selected] + visible
    for offset in range(0, len(output), BATCH_SIZE):
        yield RawBatch(records=output[offset : offset + BATCH_SIZE], checkpoint=cursor, complete=False)
    yield RawBatch(records=[], checkpoint=cursor, complete=not stopped)


def revision(raw: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def uid(*parts: object) -> str:
    return "gitlab:" + ":".join(str(part) for part in parts)


def required(raw: Mapping[str, Any], field: str) -> str:
    value = raw.get(field)
    if value is None or isinstance(value, (dict, list)):
        raise VendorContractError(f"GitLab record is missing scalar field {field!r}")
    return str(value)


def links(raw: Mapping[str, Any]) -> dict[str, str]:
    web = raw.get("web_url")
    return {"web": web} if isinstance(web, str) else {}


def data(stream_name: str, raw: Mapping[str, Any]) -> dict[str, Any]:
    return {"class_uid": _NON_OCSF_CLASS_UID, "stream": stream_name, "raw": bounded_raw(dict(raw))}


def source(stream_name: str, record_uid: str, raw: Mapping[str, Any]) -> SourceRecord:
    return SourceRecord(
        record_type=stream_name,
        uid=record_uid,
        revision=revision(raw),
        data=data(stream_name, raw),
        links=links(raw),
    )


def checked(model: BaseModel) -> BaseModel:
    """Validate against the pinned OCSF schema; a violation is a mapper bug and must surface."""
    validate_ocsf(model.model_dump(mode="json", exclude_none=True))
    return model
