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


def test_explicit_fingerprint_is_preferred_and_invalid_one_falls_back() -> None:
    from icuhub.core.sync import _identity  # noqa: PLC0415

    fp = "fp_" + "a" * 64
    base = {"unmapped": {"icuhub": {"fingerprint": fp}}, "finding_info": {"uid": "u-1", "title": "t"}}
    uid, fingerprint, _, _ = _identity(base, "nessus")
    assert fingerprint == fp

    for bad in ("fp_" + "A" * 64, "fp_" + "a" * 63, "sha256:" + "a" * 64, 7, None):
        document = {"unmapped": {"icuhub": {"fingerprint": bad}}, "finding_info": {"uid": "u-1", "title": "t"}}
        _, derived, _, _ = _identity(document, "nessus")
        assert derived != bad
        assert derived is None or derived.startswith("fp_") and len(derived) == 67


def test_targeted_mode_is_accepted_only_with_a_target() -> None:
    from icuhub.core.sync import trigger_sync  # noqa: PLC0415

    class _Session:
        async def execute(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("validation must reject before any database access")

    caller = type("Caller", (), {"tenant_id": uuid.uuid4()})()

    async def scenario() -> None:
        session: Any = _Session()
        for mode in ("bogus", "partial"):
            try:
                await trigger_sync(session, caller, uuid.uuid4(), "findings", target_id=uuid.uuid4(), mode=mode)
            except ValueError as exc:
                assert "targeted" in str(exc)
            else:
                raise AssertionError(f"mode {mode!r} must be rejected")
        try:
            await trigger_sync(session, caller, uuid.uuid4(), "findings", target_id=None, mode="targeted")
        except ValueError as exc:
            assert "target_id" in str(exc)
        else:
            raise AssertionError("targeted without a target must be rejected")

    asyncio.run(scenario())


_COMMIT_SHA = "b" * 40


def test_commit_override_requires_incremental_mode_a_target_and_a_full_sha() -> None:
    from icuhub.core.sync import trigger_sync  # noqa: PLC0415

    class _Session:
        async def execute(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("validation must reject before any database access")

    caller = type("Caller", (), {"tenant_id": uuid.uuid4()})()
    cases: list[tuple[dict[str, Any], str]] = [
        ({"target_id": None, "mode": "incremental", "commit_sha": _COMMIT_SHA}, "target_id"),
        ({"target_id": uuid.uuid4(), "mode": "full", "commit_sha": _COMMIT_SHA}, "incremental"),
        ({"target_id": uuid.uuid4(), "mode": "incremental", "commit_sha": "ABC"}, "40-character"),
        ({"target_id": uuid.uuid4(), "mode": "incremental", "commit_sha": "B" * 40}, "40-character"),
    ]

    async def scenario() -> None:
        session: Any = _Session()
        for kwargs, needle in cases:
            try:
                await trigger_sync(session, caller, uuid.uuid4(), "findings", **kwargs)
            except ValueError as exc:
                assert needle in str(exc), str(exc)
            else:
                raise AssertionError(f"{kwargs!r} must be rejected")

    asyncio.run(scenario())


def test_trigger_sync_hides_connections_of_other_tenants(tmp_path: Any, clean_database: None) -> None:
    from icuhub.core.sync import trigger_sync  # noqa: PLC0415
    from icuhub.kit.errors import NotFound  # noqa: PLC0415

    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": []}
        _services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            try:
                await trigger_sync(session, caller_for(uuid.uuid4()), connection.id, "findings")
            except NotFound:
                pass
            else:
                raise AssertionError("a connection owned by another tenant must not be triggered")

    asyncio.run(scenario())


def test_commit_partition_separates_commit_state_from_target_state() -> None:
    from icuhub.core.sync import _commit_partition  # noqa: PLC0415

    assert _commit_partition(None) == ""
    assert _commit_partition(_COMMIT_SHA) == f"commit:{_COMMIT_SHA}"


def test_commit_scoped_run_never_fans_out_without_its_target(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": []}
        services, tenant_id, connection = await _setup(tmp_path, state)
        payload = _payload(tenant_id, connection) | {"commit_sha": _COMMIT_SHA, "target_id": str(uuid.uuid4())}
        result = await run_sync_job(payload)
        assert result == {"skipped": True}, result
        async with session_scope(tenant_id) as session:
            assert (await session.execute(select(StreamState))).scalars().first() is None

    asyncio.run(scenario())


def test_targeted_run_never_closes_absence(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        from icuhub.storage.models import SyncRun  # noqa: PLC0415

        state: dict[str, Any] = {"issues": [], "findings": [finding("f-1"), finding("f-2", cve="CVE-2026-0002")]}
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            await run_sync_job(_payload(tenant_id, connection, mode="full"))
        state["findings"] = [finding("f-1")]
        async with session_scope(tenant_id) as session:
            full_at = (await session.execute(select(StreamState))).scalar_one().last_full_at
            assert full_at is not None
        async with session_scope(tenant_id) as session:
            result = await run_sync_job(_payload(tenant_id, connection, mode="targeted"))
            assert result["outcome"] == "succeeded", result
            rows = {f.source_uid: f for f in (await session.execute(select(Finding))).scalars().all()}
            assert rows["f-2"].status != "resolved_by_source", "a targeted read must not authorize absence closure"
            run = (await session.execute(select(SyncRun).where(SyncRun.mode == "targeted"))).scalar_one()
            assert run.completeness != "complete"
            state_row = (await session.execute(select(StreamState))).scalar_one()
            assert state_row.last_full_at == full_at, "a targeted run must not advance last_full_at"

    asyncio.run(scenario())


def test_each_sync_page_links_one_audit_record_to_its_raw_digest(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        from icuhub.storage.models import AuditRecord  # noqa: PLC0415

        state: dict[str, Any] = {"issues": [], "findings": [finding("f-1")]}
        services, tenant_id, connection = await _setup(tmp_path, state)
        async with session_scope(tenant_id) as session:
            first = await run_sync_job(_payload(tenant_id, connection))
            assert first["outcome"] == "succeeded", first
        state["findings"] = [finding("f-1"), finding("f-2", cve="CVE-2026-0002")]
        async with session_scope(tenant_id) as session:
            second = await run_sync_job(_payload(tenant_id, connection))
            assert second["outcome"] == "succeeded", second
            raws = (await session.execute(select(RawBatch).order_by(RawBatch.created_at))).scalars().all()
            pages = (
                (await session.execute(select(AuditRecord).where(AuditRecord.operation == "sync.page")))
                .scalars()
                .all()
            )
            assert len(raws) == 2, "each page must persist its own raw batch"
            assert len(pages) == len(raws), "each raw batch must have exactly one sync.page audit record"
            by_raw = {page.detail_json["raw_batch_id"]: page for page in pages}
            assert len(by_raw) == len(raws), "audit records must not share a raw batch"
            for raw in raws:
                page = by_raw[str(raw.id)]
                assert page.detail_json["raw_digest"] == raw.digest
                assert page.detail_json["record_count"] == raw.record_count
                assert page.detail_json["stream"] == raw.stream
                assert "seen_uids" not in page.detail_json, "audit detail must not embed the seen-uid set"
                assert "audit" not in str(page.detail_json.get("records", "")), "audit detail must not nest audit rows"

    asyncio.run(scenario())
