"""Sync engine: one commit path for poll, webhook, import, and replay (FR-ING-07..12)."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.auth_types import Caller
from icuhub.core.correlation import link_finding
from icuhub.core.credentials import EncryptedBlob
from icuhub.core.outbox import add_event
from icuhub.core.queue import DuplicateActiveJob, enqueue
from icuhub.core.services import get_services
from icuhub.kit.connector import Connector
from icuhub.kit.errors import NotFound, VendorContractError
from icuhub.kit.types import MapContext, SourceRecord, TicketRecord
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    Connection,
    Finding,
    QuarantineItem,
    RawBatch,
    StreamState,
    SyncRun,
)
from icuhub.storage.models import (
    SourceRecord as SourceRecordRow,
)
from icuhub.storage.models import (
    Target as TargetRow,
)
from icuhub.storage.system import due_stream_states
from icuhub_schemas.events import CloudEvent
from icuhub_schemas.fingerprint import finding_fingerprint

__all__ = [
    "JOB_HANDLERS",
    "commit_batch",
    "replay",
    "run_import_job",
    "run_replay_job",
    "run_sync_job",
    "scheduler_once",
    "submit_import",
    "trigger_sync",
]

_BATCH_SIZE = 500
_REMOVAL_BREAKER = 0.30


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _digest_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _identity(document: dict[str, Any], kind: str) -> tuple[str, str, int, str | None]:
    info = document.get("finding_info") or {}
    source_uid = str(info.get("uid") or "")
    if not source_uid:
        raise VendorContractError("finding_info.uid is required for identity")
    vulns = document.get("vulnerabilities") or []
    rule = None
    location = None
    component = None
    if vulns:
        vuln = vulns[0]
        rule = (vuln.get("cve") or {}).get("uid") or (vuln.get("cwe") or {}).get("uid")
        for code in vuln.get("affected_code") or []:
            location = (code.get("file") or {}).get("path")
            if location:
                break
        for pkg in vuln.get("affected_packages") or []:
            component = pkg.get("purl") or pkg.get("name")
            if component:
                break
    if rule is None:
        compliance = document.get("compliance") or {}
        checks = compliance.get("checks") or []
        rule = (checks[0].get("uid") if checks else None) or compliance.get("control")
    if rule is None:
        types = info.get("types") or []
        rule = types[0] if types else info.get("uid")
    resources = document.get("resources") or []
    if location is None and resources:
        location = resources[0].get("uid") or resources[0].get("name")
    fingerprint = finding_fingerprint(kind, rule, location, component)
    severity_id = int(document.get("severity_id") or 0)
    return source_uid, fingerprint, severity_id, info.get("title")


async def _store_raw(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    connection: Connection,
    *,
    origin: str,
    stream: str,
    payload: bytes,
    record_count: int,
    parser_version: str,
    sync_run_id: uuid.UUID | None,
) -> RawBatch:
    services = get_services()
    raw_id = uuid.uuid4()
    blob = await services.broker.encrypt_blob(tenant_id, raw_id, payload)
    raw = RawBatch(
        id=raw_id,
        tenant_id=tenant_id,
        connection_id=connection.id,
        sync_run_id=sync_run_id,
        origin=origin,
        stream=stream,
        digest="sha256:" + hashlib.sha256(payload).hexdigest(),
        record_count=record_count,
        parser_version=parser_version,
        kek_id=blob.kek_id,
        dek_wrapped=blob.dek_wrapped,
        nonce=blob.nonce,
        payload_enc=blob.ciphertext,
        expires_at=datetime.now(UTC) + timedelta(days=services.settings.raw_retention_days),
    )
    session.add(raw)
    await session.flush()
    return raw


async def commit_batch(
    session: AsyncSession,
    *,
    connection: Connection,
    connector: Connector,
    stream: str,
    records: list[dict[str, Any]],
    origin: str,
    sync_run_id: uuid.UUID | None = None,
    checkpoint: BaseModel | None = None,
    state: StreamState | None = None,
    expected_version: int | None = None,
    target: TargetRow | None = None,
) -> dict[str, Any]:
    """Map, quarantine, upsert, emit, and advance the checkpoint in one transaction."""
    mapper = connector.mappers()[stream]
    raw = await _store_raw(
        session,
        connection.tenant_id,
        connection,
        origin=origin,
        stream=stream,
        payload=_canonical(records).encode("utf-8"),
        record_count=len(records),
        parser_version=str(mapper.version),
        sync_run_id=sync_run_id,
    )
    ctx = MapContext(
        connection_id=str(connection.id),
        tenant_id=str(connection.tenant_id),
        connector_kind=connector.kind,
        target=None,
        received_at=datetime.now(UTC),
    )
    if target is not None:
        from icuhub.kit.types import Target  # noqa: PLC0415

        ctx = ctx.model_copy(update={"target": Target(id=str(target.id), source_uid=target.source_uid, kind=target.kind, display_name=target.display_name, attributes=target.attributes_json or {})})
    counts = {"findings": 0, "records": 0, "quarantined": 0, "unchanged": 0, "raw_batch_id": str(raw.id)}
    seen_uids: set[str] = set()
    from icuhub.core.tickets import on_ticket_record  # noqa: PLC0415

    for index, record in enumerate(records):
        try:
            objects = mapper.fn(connector, record, ctx)
        except VendorContractError as exc:
            session.add(
                QuarantineItem(
                    tenant_id=connection.tenant_id,
                    raw_batch_id=raw.id,
                    record_index=index,
                    error_class=type(exc).__name__,
                    error_detail=str(exc)[:2000],
                    mapper_version=mapper.version,
                )
            )
            counts["quarantined"] += 1
            continue
        for obj in objects:
            if isinstance(obj, SourceRecord):
                await _upsert_source_record(session, connection, raw, stream, obj)
                counts["records"] += 1
                if isinstance(obj, TicketRecord):
                    await on_ticket_record(session, connection, obj)
                continue
            document = obj.model_dump(mode="json")
            source_uid, fingerprint, severity_id, title = _identity(document, connector.kind)
            seen_uids.add(source_uid)
            revision = _digest_text(_canonical(document))
            existing = (
                await session.execute(
                    select(Finding).where(
                        Finding.connection_id == connection.id,
                        Finding.stream == stream,
                        Finding.source_uid == source_uid,
                    )
                )
            ).scalar_one_or_none()
            if existing is None:
                existing = Finding(
                    tenant_id=connection.tenant_id,
                    connection_id=connection.id,
                    target_id=target.id if target else None,
                    stream=stream,
                    source_uid=source_uid,
                    fingerprint=fingerprint,
                    ocsf_class_uid=int(document.get("class_uid") or 0),
                    severity_id=severity_id,
                    title=title,
                    ocsf_json=document,
                    revision_digest=revision,
                    raw_batch_id=raw.id,
                    mapper_version=mapper.version,
                    status="resolved_by_source" if document.get("status_id") == 2 else "open",
                )
                session.add(existing)
                await session.flush()
                case = await link_finding(session, existing)
                await _finding_event(session, existing, "icuhub.finding.upserted")
                await _enqueue_route(session, case.id, connection.tenant_id)
                counts["findings"] += 1
            elif existing.revision_digest != revision:
                existing.ocsf_json = document
                existing.revision_digest = revision
                existing.raw_batch_id = raw.id
                existing.mapper_version = mapper.version
                existing.severity_id = severity_id
                existing.title = title
                existing.last_seen = datetime.now(UTC)
                case = await link_finding(session, existing)
                await _finding_event(session, existing, "icuhub.finding.upserted")
                await _enqueue_route(session, case.id, connection.tenant_id)
                counts["findings"] += 1
            else:
                existing.last_seen = datetime.now(UTC)
                counts["unchanged"] += 1
    if state is not None and checkpoint is not None:
        if expected_version is not None and state.version != expected_version:
            raise ConflictError("stream state version mismatch")
        state.checkpoint_json = checkpoint.model_dump(mode="json")
        state.checkpoint_schema = f"{type(checkpoint).__module__}.{type(checkpoint).__name__}"
        state.version += 1
    counts["seen_uids"] = sorted(seen_uids)
    return counts


class ConflictError(Exception):  # noqa: N818  # internal signal, not part of the kit taxonomy
    """A stale writer lost the stream-state version check."""


async def _upsert_source_record(
    session: AsyncSession, connection: Connection, raw: RawBatch, stream: str, record: SourceRecord
) -> None:
    existing = (
        await session.execute(
            select(SourceRecordRow).where(
                SourceRecordRow.connection_id == connection.id,
                SourceRecordRow.record_type == record.record_type,
                SourceRecordRow.uid == record.uid,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(
            SourceRecordRow(
                tenant_id=connection.tenant_id,
                connection_id=connection.id,
                stream=stream,
                record_type=record.record_type,
                uid=record.uid,
                revision=record.revision,
                data_json=record.data,
                links_json=record.links,
                raw_batch_id=raw.id,
            )
        )
        await add_event(
            session,
            connection.tenant_id,
            CloudEvent(
                id=f"record-{connection.id}-{record.record_type}-{record.uid}-{uuid.uuid4()}",
                source=f"icuhub://connections/{connection.id}",
                type="icuhub.record.upserted",
                subject=record.uid,
                time=datetime.now(UTC),
                data={"record_type": record.record_type, "stream": stream},
            ),
        )
        return
    if existing.revision != record.revision or existing.data_json != record.data:
        existing.data_json = record.data
        existing.revision = record.revision
        existing.links_json = record.links
        existing.raw_batch_id = raw.id
    existing.last_seen = datetime.now(UTC)


async def _finding_event(session: AsyncSession, finding: Finding, event_type: str) -> None:
    await add_event(
        session,
        finding.tenant_id,
        CloudEvent(
            id=f"finding-{finding.id}-{finding.revision_digest[:20]}",
            source=f"icuhub://findings/{finding.id}",
            type=event_type,
            subject=str(finding.id),
            time=datetime.now(UTC),
            data={
                "connection_id": str(finding.connection_id),
                "fingerprint": finding.fingerprint,
                "correlation_key": finding.correlation_key,
                "severity_id": finding.severity_id,
                "class_uid": finding.ocsf_class_uid,
            },
        ),
    )


async def _enqueue_route(session: AsyncSession, case_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    try:
        await enqueue(
        session,
        "tickets",
        "route_case",
        {"case_id": str(case_id), "tenant_id": str(tenant_id)},
        tenant_id=tenant_id,
            dedupe_key=f"{tenant_id}:route:{case_id}",
        )
    except DuplicateActiveJob:
        return


async def trigger_sync(
    session: AsyncSession,
    caller: Any,
    connection_id: uuid.UUID,
    stream: str,
    *,
    target_id: uuid.UUID | None = None,
    mode: str = "incremental",
) -> uuid.UUID:
    if mode not in ("incremental", "full"):
        raise ValueError("mode must be incremental or full")
    return await enqueue(
        session,
        "sync",
        "sync",
        {
            "connection_id": str(connection_id),
            "stream": stream,
            "tenant_id": str(caller.tenant_id),
            "target_id": str(target_id) if target_id else None,
            "mode": mode,
        },
        tenant_id=caller.tenant_id,
        dedupe_key=f"{caller.tenant_id}:sync:{connection_id}:{stream}:{target_id}:{mode}",
    )


async def _resolve_absent(
    session: AsyncSession,
    connection: Connection,
    stream: str,
    target: TargetRow | None,
    seen: set[str],
    run: SyncRun,
) -> str:
    query = select(Finding).where(
        Finding.connection_id == connection.id,
        Finding.stream == stream,
        Finding.status != "resolved_by_source",
    )
    if target is not None:
        query = query.where(Finding.target_id == target.id)
    open_findings = list((await session.execute(query)).scalars().all())
    absent = [f for f in open_findings if f.source_uid not in seen]
    if not absent:
        return "complete"
    if open_findings and not seen:
        run.outcome = "held"
        run.error_detail = "removal circuit breaker: complete snapshot returned zero records"
        return "held"
    if len(absent) > max(1, int(len(open_findings) * _REMOVAL_BREAKER)):
        run.outcome = "held"
        run.error_detail = f"removal circuit breaker: {len(absent)} of {len(open_findings)} would resolve"
        return "held"
    for finding in absent:
        finding.status = "resolved_by_source"
        finding.resolved_at = datetime.now(UTC)
        await _finding_event(session, finding, "icuhub.finding.resolved")
    return "complete"


async def _discover_targets(session: AsyncSession, connection: Connection, connector: Connector) -> list[TargetRow]:
    """Refresh the connection's target inventory from connector discovery."""
    rows: list[TargetRow] = []
    async for record in connector.discover():
        row = (
            await session.execute(
                select(TargetRow).where(
                    TargetRow.connection_id == connection.id, TargetRow.source_uid == record.source_uid
                )
            )
        ).scalar_one_or_none()
        if row is None:
            row = TargetRow(
                tenant_id=connection.tenant_id,
                connection_id=connection.id,
                source_uid=record.source_uid,
                kind=record.kind,
                display_name=record.display_name,
                attributes_json=record.attributes,
            )
            session.add(row)
        else:
            row.kind = record.kind
            row.display_name = record.display_name
            row.attributes_json = record.attributes
            row.missing_since = None
        row.last_seen_at = datetime.now(UTC)
        await session.flush()
        if row.included and not row.paused:
            rows.append(row)
    return rows


def _stream_target(row: TargetRow | None) -> Any:
    if row is None:
        return None
    from icuhub.kit.types import Target  # noqa: PLC0415

    return Target(
        id=str(row.id),
        source_uid=row.source_uid,
        kind=row.kind,
        display_name=row.display_name,
        attributes=row.attributes_json or {},
    )


async def _run_stream_target(
    session: AsyncSession,
    *,
    connection: Connection,
    connector: Connector,
    stream: str,
    mode: str,
    target_row: TargetRow | None,
) -> dict[str, Any]:
    """Run one stream for one target with its own stream state and sync run."""
    spec = connector.streams()[stream]
    target = _stream_target(target_row)
    target_key = str(target_row.id) if target_row else ""
    state = (
        await session.execute(
            select(StreamState).where(
                StreamState.connection_id == connection.id,
                StreamState.target_key == target_key,
                StreamState.stream == stream,
            )
        )
    ).scalar_one_or_none()
    if state is None:
        state = StreamState(
            tenant_id=connection.tenant_id,
            connection_id=connection.id,
            target_id=target_row.id if target_row else None,
            target_key=target_key,
            stream=stream,
        )
        session.add(state)
        await session.flush()
    run = SyncRun(
        tenant_id=connection.tenant_id,
        stream_state_id=state.id,
        connection_id=connection.id,
        stream=stream,
        mode=mode,
    )
    session.add(run)
    await session.flush()
    checkpoint = spec.cursor.model_validate(state.checkpoint_json) if state.checkpoint_json else None
    version = state.version
    totals = {"findings": 0, "records": 0, "quarantined": 0, "unchanged": 0}
    seen: set[str] = set()
    complete = False
    try:
        async for batch in getattr(connector, spec.fn.__name__)(target, checkpoint, mode):
            result = await commit_batch(
                session,
                connection=connection,
                connector=connector,
                stream=stream,
                records=batch.records,
                origin="stream",
                sync_run_id=run.id,
                checkpoint=batch.checkpoint,
                state=state,
                expected_version=version,
                target=target_row,
            )
            version = state.version
            seen.update(result["seen_uids"])
            for key in totals:
                totals[key] += result[key]
            complete = complete or batch.complete
        if mode == "full" and complete:
            outcome = await _resolve_absent(session, connection, stream, target_row, seen, run)
            run.completeness = "complete" if outcome == "complete" else "partial"
            if outcome == "complete":
                state.last_full_at = datetime.now(UTC)
        run.outcome = run.outcome if run.outcome == "held" else "succeeded"
        run.completeness = "complete" if (mode == "full" and complete) else run.completeness
        state.health = "degraded" if totals["quarantined"] else "healthy"
        state.last_success_at = datetime.now(UTC)
    except ConflictError:
        run.outcome = "superseded"
        run.error_class = "ConflictError"
        state.health = "degraded"
    except Exception as exc:  # noqa: BLE001 - failure class is recorded at this boundary
        run.outcome = "failed"
        run.error_class = type(exc).__name__
        run.error_detail = str(exc)[:2000]
        state.health = "degraded"
    run.counts_json = totals
    run.finished_at = datetime.now(UTC)
    state.next_run_at = datetime.now(UTC) + timedelta(seconds=state.interval_s)
    return {"outcome": run.outcome, **totals}


async def run_sync_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    """Worker handler for the ``sync`` job kind.

    Target-scoped streams run once per discovered target when no explicit target is given;
    every target gets its own stream state, sync run, and checkpoint.
    """
    services = get_services()
    tenant_id = uuid.UUID(payload["tenant_id"])
    connection_id = uuid.UUID(payload["connection_id"])
    stream = payload["stream"]
    mode = payload.get("mode", "incremental")
    target_id = uuid.UUID(payload["target_id"]) if payload.get("target_id") else None
    async with session_scope(tenant_id) as session:
        connection = await session.get(Connection, connection_id)
        if connection is None:
            return {"skipped": True}
        connector = await services.runtime.open(session, tenant_id, connection.id)
        spec = connector.streams()[stream]
        target = await session.get(TargetRow, target_id) if target_id else None
        if spec.requires_target:
            if target:
                targets = [target]
            elif type(connector).discover is not Connector.discover:
                targets = await _discover_targets(session, connection, connector)
            else:
                # Connection-wide stream on a connector with no discovery surface.
                targets = [None]
        else:
            targets = [None]
        totals = {"findings": 0, "records": 0, "quarantined": 0, "unchanged": 0}
        outcome = "succeeded"
        for row in targets:
            result = await _run_stream_target(
                session, connection=connection, connector=connector, stream=stream, mode=mode, target_row=row
            )
            for key in totals:
                totals[key] += result[key]
            if result["outcome"] == "failed":
                outcome = "failed"
            elif result["outcome"] in ("held", "superseded") and outcome != "failed":
                outcome = result["outcome"]
        return {"outcome": outcome, **totals}


async def replay(session: AsyncSession, caller: Any, raw_batch_id: uuid.UUID) -> dict[str, Any]:
    """Re-map a stored raw batch with the current mapper; no vendor call."""
    services = get_services()
    raw = await session.get(RawBatch, raw_batch_id)
    if raw is None or raw.tenant_id != caller.tenant_id:
        raise VendorContractError("raw batch not found")
    payload = await services.broker.decrypt_blob(
        caller.tenant_id,
        raw.id,
        EncryptedBlob(kek_id=raw.kek_id, dek_wrapped=raw.dek_wrapped, nonce=raw.nonce, ciphertext=raw.payload_enc),
    )
    records = json.loads(payload.decode("utf-8"))
    connection = await session.get(Connection, raw.connection_id)
    connector = await services.runtime.open(session, caller.tenant_id, connection.id)
    return await commit_batch(
        session,
        connection=connection,
        connector=connector,
        stream=raw.stream,
        records=records,
        origin="replay",
    )


async def run_replay_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    async with session_scope(uuid.UUID(payload["tenant_id"])) as session:
        caller = Caller(id="replayer", tenant_id=uuid.UUID(payload["tenant_id"]), roles=frozenset({"system"}))
        return await replay(session, caller, uuid.UUID(payload["raw_batch_id"]))


async def submit_import(
    session: AsyncSession, caller: Any, connection_id: uuid.UUID, importer: str, filename: str, data: bytes
) -> Any:
    """Store an uploaded report encrypted and enqueue its parse job (deduped by digest)."""
    from icuhub.storage.models import FileImport  # noqa: PLC0415

    services = get_services()
    connection = await session.get(Connection, connection_id)
    if connection is None or connection.tenant_id != caller.tenant_id:
        raise NotFound("connection not found")
    cls = services.runtime._class(connection)
    spec = cls.importers().get(importer)
    if spec is None:
        raise NotFound(f"{connection.kind} has no importer {importer!r}")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    existing = (
        await session.execute(
            select(FileImport).where(
                FileImport.connection_id == connection_id,
                FileImport.importer == importer,
                FileImport.digest == digest,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    raw = await _store_raw(
        session,
        caller.tenant_id,
        connection,
        origin="import",
        stream=spec.stream,
        payload=data,
        record_count=0,
        parser_version="0",
        sync_run_id=None,
    )
    record = FileImport(
        tenant_id=caller.tenant_id,
        connection_id=connection_id,
        importer=importer,
        filename=filename,
        digest=digest,
        size_bytes=len(data),
        raw_batch_id=raw.id,
    )
    session.add(record)
    await session.flush()
    await enqueue(
        session,
        "imports",
        "import",
        {"file_import_id": str(record.id), "tenant_id": str(caller.tenant_id)},
        tenant_id=caller.tenant_id,
        dedupe_key=f"{caller.tenant_id}:import:{record.id}",
    )
    return record


async def run_import_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    """Worker handler for the ``import`` job kind."""
    from icuhub.kit.types import ImportedFile  # noqa: PLC0415
    from icuhub.storage.models import FileImport  # noqa: PLC0415

    services = get_services()
    tenant_id = uuid.UUID(payload["tenant_id"])
    async with session_scope(tenant_id) as session:
        record = await session.get(FileImport, uuid.UUID(payload["file_import_id"]))
        if record is None or record.state == "done":
            return {"skipped": True}
        raw = await session.get(RawBatch, record.raw_batch_id)
        if raw is None:
            record.state = "failed"
            record.error = "raw batch missing"
            return {"state": "failed"}
        data = await services.broker.decrypt_blob(
            tenant_id,
            raw.id,
            EncryptedBlob(kek_id=raw.kek_id, dek_wrapped=raw.dek_wrapped, nonce=raw.nonce, ciphertext=raw.payload_enc),
        )
        connection = await session.get(Connection, record.connection_id)
        connector = await services.runtime.open(session, tenant_id, connection.id)
        spec = connector.importers()[record.importer]
        imported = ImportedFile(filename=record.filename, media_type=None, data=data)
        totals = {"findings": 0, "records": 0, "quarantined": 0, "unchanged": 0}
        buffer: list[dict[str, Any]] = []
        try:
            async for raw_record in getattr(connector, spec.fn.__name__)(imported):
                buffer.append(raw_record)
                if len(buffer) >= _BATCH_SIZE:
                    result = await commit_batch(
                        session, connection=connection, connector=connector, stream=spec.stream,
                        records=buffer, origin="import",
                    )
                    for key in totals:
                        totals[key] += result[key]
                    buffer = []
            if buffer:
                result = await commit_batch(
                    session, connection=connection, connector=connector, stream=spec.stream,
                    records=buffer, origin="import",
                )
                for key in totals:
                    totals[key] += result[key]
            record.state = "done"
        except Exception as exc:  # noqa: BLE001 - failure class is recorded at this boundary
            record.state = "failed"
            record.error = f"{type(exc).__name__}: {exc}"[:2000]
        record.counts_json = totals
        record.finished_at = datetime.now(UTC)
        return {"state": record.state, **totals}


async def scheduler_once(now: datetime | None = None, limit: int = 100) -> int:
    """Enqueue one job per due stream state; returns the number scheduled."""
    now = now or datetime.now(UTC)
    scheduled = 0
    for due in await due_stream_states(now, limit):
        async with session_scope(due.tenant_id) as session:
            state = await session.get(StreamState, due.id)
            if state is None:
                continue
            mode = "incremental"
            if state.last_full_at is None or now - state.last_full_at > timedelta(seconds=state.full_interval_s):
                mode = "full"
            await enqueue(
                session,
                "sync",
                "sync",
                {
                    "connection_id": str(state.connection_id),
                    "stream": state.stream,
                    "tenant_id": str(state.tenant_id),
                    "target_id": str(state.target_id) if state.target_id else None,
                    "mode": mode,
                },
                tenant_id=state.tenant_id,
                dedupe_key=f"{state.tenant_id}:sync:{state.id}",
            )
            state.next_run_at = now + timedelta(seconds=state.interval_s)
            scheduled += 1
    return scheduled


JOB_HANDLERS = {"sync": run_sync_job, "replay": run_replay_job, "import": run_import_job}
