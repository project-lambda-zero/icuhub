"""Sync engine: atomic commits, dedupe, quarantine, full-snapshot closure, imports."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from sqlalchemy import select

from icuhub.core.sync import run_import_job, run_sync_job, submit_import
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    CaseMember,
    CorrelationCase,
    FileImport,
    Finding,
    OutboxEvent,
    QuarantineItem,
    RawBatch,
    StreamState,
    Tenant,
)
from tests.core.helpers import caller_for, finding, make_services, new_connection, vendor_transport


async def _setup(tmp_path: Any, state: dict[str, Any]) -> tuple[Any, uuid.UUID, Any]:
    services = make_services(vendor_transport(state), tmp_path / "kek")
    tenant_id = uuid.uuid4()
    async with session_scope(tenant_id) as session:
        session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
        await session.flush()
        connection = await new_connection(session, services, tenant_id)
    return services, tenant_id, connection


def _payload(tenant_id: uuid.UUID, connection: Any, mode: str = "incremental") -> dict[str, Any]:
    return {
        "tenant_id": str(tenant_id),
        "connection_id": str(connection.id),
        "stream": "findings",
        "mode": mode,
        "target_id": None,
    }


def test_incremental_commit_and_idempotent_rerun(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": [finding("f-1"), finding("f-2")]}
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection))
            assert result["outcome"] == "succeeded", result
            assert result["findings"] == 2
            rows = (await session.execute(select(Finding))).scalars().all()
            assert len(rows) == 2
            assert rows[0].correlation_key == rows[1].correlation_key
            raw = (await session.execute(select(RawBatch))).scalars().all()
            assert len(raw) == 1 and raw[0].record_count == 2
            events = (await session.execute(select(OutboxEvent))).scalars().all()
            assert any(e.event_json["type"] == "icuhub.finding.upserted" for e in events)
            state_row = (await session.execute(select(StreamState))).scalar_one()
            assert state_row.checkpoint_json["ts"] is not None
            assert state_row.version == 1
        async with session_scope(tenant_id) as session:
            again = await run_sync_job(_payload(tenant_id, connection))
            assert again["unchanged"] == 2
            assert again["findings"] == 0
            assert (await session.execute(select(Finding))).scalars().all()
            upserts = [
                e
                for e in (await session.execute(select(OutboxEvent))).scalars().all()
                if e.event_json["type"] == "icuhub.finding.upserted"
            ]
            assert len(upserts) == 2

    asyncio.run(scenario())


def test_quarantine_and_full_snapshot_rules(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": [finding("f-1"), finding("bad", bad=True)]}
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection))
            assert result["quarantined"] == 1
            assert result["findings"] == 1
            assert (await session.execute(select(QuarantineItem))).scalars().one()
            state_row = (await session.execute(select(StreamState))).scalar_one()
            assert state_row.health == "degraded"
        state["findings"] = [finding("f-1")]
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection, mode="full"))
            assert result["outcome"] == "succeeded"
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection, mode="full"))
            assert result["outcome"] == "succeeded"
        state["findings"] = []
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection, mode="full"))
            assert result["outcome"] == "held"
            open_rows = [f for f in (await session.execute(select(Finding))).scalars().all() if f.status != "resolved_by_source"]
            assert open_rows, "breaker must not resolve on zero-record snapshot"

    asyncio.run(scenario())


def test_ocsf_status_id_maps_in_progress_open_and_resolved_closed(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": [finding("f-s", status_id=2)]}
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection))
            row = (await session.execute(select(Finding).where(Finding.source_uid == "f-s"))).scalar_one()
            assert row.status == "open", "OCSF 2 (In Progress) must remain open"
            assert row.resolved_at is None
        state["findings"] = [finding("f-s", status_id=4)]
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection))
            row = (await session.execute(select(Finding).where(Finding.source_uid == "f-s"))).scalar_one()
            assert row.status == "resolved_by_source", "OCSF 4 (Resolved) must close the finding"
            assert row.resolved_at is not None
        state["findings"] = [finding("f-s", status_id=2)]
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection))
            row = (await session.execute(select(Finding).where(Finding.source_uid == "f-s"))).scalar_one()
            assert row.status == "open", "a finding that reappears in progress must reopen"
            assert row.resolved_at is None

    asyncio.run(scenario())


def test_full_run_resolves_absent_only_when_complete(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": [finding("f-1"), finding("f-2", cve="CVE-2026-0002")]}
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection, mode="full"))
        state["findings"] = [finding("f-1")]
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection, mode="full"))
            assert result["outcome"] == "succeeded"
            rows = {f.source_uid: f for f in (await session.execute(select(Finding))).scalars().all()}
            assert rows["f-2"].status == "resolved_by_source"
            assert rows["f-1"].status != "resolved_by_source"

    asyncio.run(scenario())


def test_absent_finding_that_reappears_unchanged_reopens(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": [finding("f-1"), finding("f-2", cve="CVE-2026-0002")]}
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection, mode="full"))
        state["findings"] = [finding("f-1")]
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection, mode="full"))
            row = (await session.execute(select(Finding).where(Finding.source_uid == "f-2"))).scalar_one()
            assert row.status == "resolved_by_source"
        state["findings"] = [finding("f-1"), finding("f-2", cve="CVE-2026-0002")]
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection, mode="full"))
            assert result["outcome"] == "succeeded"
            row = (await session.execute(select(Finding).where(Finding.source_uid == "f-2"))).scalar_one()
            assert row.status == "open", "a reappearing finding with an unchanged document must reopen"
            assert row.resolved_at is None

    asyncio.run(scenario())


def test_absence_resolves_case_only_when_last_member_leaves(tmp_path: Any, clean_database: None) -> None:
    async def case_state(session: Any, uid: str) -> tuple[uuid.UUID, str]:
        finding_row = (await session.execute(select(Finding).where(Finding.source_uid == uid))).scalar_one()
        member = (await session.execute(select(CaseMember).where(CaseMember.finding_id == finding_row.id))).scalar_one()
        case = (await session.execute(select(CorrelationCase).where(CorrelationCase.id == member.case_id))).scalar_one()
        return case.id, case.detection_state

    async def scenario() -> None:
        # f-1 and f-2 share a CVE and purl, so they share one case; f-3 keeps the snapshot non-empty.
        state: dict[str, Any] = {
            "issues": [],
            "findings": [finding("f-1"), finding("f-2"), finding("f-3", cve="CVE-2026-0003")],
        }
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection, mode="full"))
            shared_case, initial_state = await case_state(session, "f-1")
            assert initial_state == "open"
            assert await case_state(session, "f-2") == (shared_case, "open")

        state["findings"] = [finding("f-2"), finding("f-3", cve="CVE-2026-0003")]
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection, mode="full"))
            assert await case_state(session, "f-2") == (shared_case, "open")

        state["findings"] = [finding("f-3", cve="CVE-2026-0003")]
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection, mode="full"))
            assert result["outcome"] == "succeeded"
            assert await case_state(session, "f-2") == (shared_case, "resolved_by_source")
            members = (await session.execute(select(CaseMember).where(CaseMember.case_id == shared_case))).scalars().all()
            assert len(members) == 2

        async with session_scope(tenant_id) as session:
            events_before = len((await session.execute(select(OutboxEvent).where(OutboxEvent.tenant_id == tenant_id))).scalars().all())
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection, mode="full"))
            assert await case_state(session, "f-2") == (shared_case, "resolved_by_source")
            events_after = len((await session.execute(select(OutboxEvent).where(OutboxEvent.tenant_id == tenant_id))).scalars().all())
        assert events_after == events_before, "replaying the same complete snapshot must emit nothing"

    asyncio.run(scenario())


def test_import_dedupe_and_parse(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": []}
        services, tenant_id, connection = await _setup(tmp_path, state)
        data = json.dumps({"items": [finding("imp-1"), finding("imp-2")]}).encode()
        async with session_scope(tenant_id) as session:
            record = await submit_import(session, caller_for(tenant_id), connection.id, "sample_report", "r.json", data)
            assert record.state == "queued"
            duplicate = await submit_import(session, caller_for(tenant_id), connection.id, "sample_report", "r.json", data)
            assert duplicate.id == record.id
        async with session_scope(tenant_id) as session:
            result = await run_import_job({"file_import_id": str(record.id), "tenant_id": str(tenant_id)})
            assert result["state"] == "done", result
            assert result["findings"] == 2
            stored = await session.get(FileImport, record.id)
            assert stored.counts_json["findings"] == 2

    asyncio.run(scenario())


def test_target_discovery_runs_each_target(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        from icuhub.storage.models import SyncRun, Target  # noqa: PLC0415

        state: dict[str, Any] = {"issues": [], "findings": []}
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection).copy() | {"stream": "targeted_findings", "mode": "full"})
            assert result["outcome"] == "succeeded", result
            assert result["findings"] == 2
            targets = (await session.execute(select(Target))).scalars().all()
            assert {t.source_uid for t in targets} == {"proj-1", "proj-2"}
            runs = (await session.execute(select(SyncRun))).scalars().all()
            assert len(runs) == 2
            states = (await session.execute(select(StreamState))).scalars().all()
            assert len(states) == 2
            uids = {f.source_uid for f in (await session.execute(select(Finding))).scalars().all()}
            assert uids == {"proj-1-finding", "proj-2-finding"}

    asyncio.run(scenario())
