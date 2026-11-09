"""Behavioural tests for the per-tenant audit hash chain (FR-AUD-02, FR-AUD-05).

Every test runs against real PostgreSQL. Appends and reads go through the
``icuhub_app`` role under row-level security; tampering is performed by the owner
role with the ``audit_append_only`` trigger disabled inside the same transaction
that changes the row, so the trigger is restored on commit or rollback.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from icuhub.core.audit import GENESIS_PREV_HASH, VerifyResult, append, verify_chain
from icuhub.storage.db import create_engine, session_scope
from icuhub.storage.models import AuditRecord, Tenant

pytestmark = pytest.mark.usefixtures("clean_database")

_TS = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


async def _insert_tenant(owner: AsyncEngine) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with AsyncSession(owner) as session, session.begin():
        session.add(
            Tenant(id=tenant_id, slug=f"audit-{tenant_id.hex[:12]}", display_name="Audit test")
        )
    return tenant_id


async def _append_records(app: AsyncEngine, tenant_id: uuid.UUID, count: int) -> None:
    for index in range(count):
        async with session_scope(tenant_id, engine=app) as session:
            await append(
                session,
                tenant_id,
                ts=_TS + timedelta(seconds=index),
                caller_id="svc-scanner",
                operation=f"vendor.op_{index}",
                status="succeeded",
                detail_json={"index": index},
            )


async def _owner_edit(
    owner: AsyncEngine, statements: list[tuple[str, dict[str, Any]]]
) -> None:
    """Run row edits as the owner with the append-only trigger off for this transaction only.

    PostgreSQL DDL is transactional, so an exception before the ENABLE statement rolls
    back the DISABLE as well and the trigger is never left off.
    """

    async with AsyncSession(owner) as session, session.begin():
        await session.execute(text("ALTER TABLE audit_record DISABLE TRIGGER audit_append_only"))
        for sql, params in statements:
            await session.execute(text(sql), params)
        await session.execute(text("ALTER TABLE audit_record ENABLE TRIGGER audit_append_only"))


async def _read_rows(app: AsyncEngine, tenant_id: uuid.UUID) -> list[AuditRecord]:
    async with session_scope(tenant_id, engine=app) as session:
        rows = await session.execute(
            select(AuditRecord).where(AuditRecord.tenant_id == tenant_id).order_by(AuditRecord.seq)
        )
        return list(rows.scalars().all())


async def _verify(app: AsyncEngine, tenant_id: uuid.UUID) -> VerifyResult:
    async with session_scope(tenant_id, engine=app) as session:
        return await verify_chain(session, tenant_id)


def test_valid_chain_links_each_record_and_verifies(
    owner_database_url: str, app_database_url: str
) -> None:
    async def scenario() -> None:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = await _insert_tenant(owner)
            await _append_records(app, tenant_id, 3)
            rows = await _read_rows(app, tenant_id)
            result = await _verify(app, tenant_id)
        finally:
            await owner.dispose()
            await app.dispose()

        assert [row.seq for row in rows] == [1, 2, 3]
        assert rows[0].prev_hash == GENESIS_PREV_HASH
        assert rows[1].prev_hash == rows[0].hash
        assert rows[2].prev_hash == rows[1].hash
        assert all(row.hash.startswith("sha256:") and len(row.hash) == 71 for row in rows)
        assert result.ok is True
        assert result.checked == 3
        assert result.failures == ()

    asyncio.run(scenario())


def test_empty_tenant_chain_verifies_with_zero_records(
    owner_database_url: str, app_database_url: str
) -> None:
    async def scenario() -> None:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = await _insert_tenant(owner)
            result = await _verify(app, tenant_id)
        finally:
            await owner.dispose()
            await app.dispose()

        assert result.ok is True
        assert result.checked == 0
        assert result.failures == ()

    asyncio.run(scenario())


def test_concurrent_appends_produce_a_gap_free_chain(
    owner_database_url: str, app_database_url: str
) -> None:
    async def one_append(app: AsyncEngine, tenant_id: uuid.UUID, index: int) -> None:
        async with session_scope(tenant_id, engine=app) as session:
            await append(
                session,
                tenant_id,
                ts=_TS,
                caller_id="svc-scanner",
                operation="vendor.parallel",
                status="succeeded",
                detail_json={"index": index},
            )

    async def scenario() -> None:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = await _insert_tenant(owner)
            await asyncio.gather(*(one_append(app, tenant_id, index) for index in range(8)))
            rows = await _read_rows(app, tenant_id)
            result = await _verify(app, tenant_id)
        finally:
            await owner.dispose()
            await app.dispose()

        assert [row.seq for row in rows] == list(range(1, 9))
        assert result.ok is True, result.failures

    asyncio.run(scenario())


def test_modified_row_is_reported_with_its_sequence(
    owner_database_url: str, app_database_url: str
) -> None:
    async def scenario() -> VerifyResult:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = await _insert_tenant(owner)
            await _append_records(app, tenant_id, 3)
            await _owner_edit(
                owner,
                [
                    (
                        "UPDATE audit_record SET caller_id = 'forged' "
                        "WHERE tenant_id = :tenant_id AND seq = 2",
                        {"tenant_id": tenant_id},
                    )
                ],
            )
            return await _verify(app, tenant_id)
        finally:
            await owner.dispose()
            await app.dispose()

    result = asyncio.run(scenario())

    assert result.ok is False
    assert [failure.seq for failure in result.failures] == [2]
    assert "hash mismatch" in result.failures[0].reason


def test_sequence_gap_is_reported_and_not_hidden(
    owner_database_url: str, app_database_url: str
) -> None:
    async def scenario() -> VerifyResult:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = await _insert_tenant(owner)
            await _append_records(app, tenant_id, 3)
            await _owner_edit(
                owner,
                [
                    (
                        "DELETE FROM audit_record WHERE tenant_id = :tenant_id AND seq = 2",
                        {"tenant_id": tenant_id},
                    )
                ],
            )
            return await _verify(app, tenant_id)
        finally:
            await owner.dispose()
            await app.dispose()

    result = asyncio.run(scenario())

    assert result.ok is False
    gap = [failure for failure in result.failures if failure.seq == 3]
    assert any(
        failure.reason == "sequence gap: expected seq 2, found 3" for failure in gap
    ), result.failures


def test_purged_row_keeps_hash_linkage_verifiable(
    owner_database_url: str, app_database_url: str
) -> None:
    async def scenario() -> tuple[VerifyResult, VerifyResult]:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = await _insert_tenant(owner)
            await _append_records(app, tenant_id, 3)
            await _owner_edit(
                owner,
                [
                    (
                        "UPDATE audit_record SET detail_json = CAST('{}' AS jsonb) "
                        "WHERE tenant_id = :tenant_id AND seq = 2",
                        {"tenant_id": tenant_id},
                    )
                ],
            )
            purged_ok = await _verify(app, tenant_id)
            await _owner_edit(
                owner,
                [
                    (
                        "UPDATE audit_record SET hash = 'not-a-hash' "
                        "WHERE tenant_id = :tenant_id AND seq = 2",
                        {"tenant_id": tenant_id},
                    )
                ],
            )
            purged_bad_hash = await _verify(app, tenant_id)
            return purged_ok, purged_bad_hash
        finally:
            await owner.dispose()
            await app.dispose()

    purged_ok, purged_bad_hash = asyncio.run(scenario())

    assert purged_ok.ok is True, purged_ok.failures
    assert purged_ok.checked == 3
    assert purged_bad_hash.ok is False
    assert [failure.seq for failure in purged_bad_hash.failures] == [2, 3]
    assert "malformed stored hash" in purged_bad_hash.failures[0].reason
    assert "previous hash mismatch" in purged_bad_hash.failures[1].reason


def test_append_rejects_empty_detail_and_naive_timestamps(
    owner_database_url: str, app_database_url: str
) -> None:
    async def scenario() -> tuple[str, str, int]:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = await _insert_tenant(owner)
            with pytest.raises(ValueError, match="purge marker") as empty_detail:
                async with session_scope(tenant_id, engine=app) as session:
                    await append(
                        session,
                        tenant_id,
                        ts=_TS,
                        caller_id="svc-scanner",
                        operation="vendor.op",
                        status="succeeded",
                        detail_json={},
                    )
            with pytest.raises(ValueError, match="timezone-aware") as naive_ts:
                async with session_scope(tenant_id, engine=app) as session:
                    await append(
                        session,
                        tenant_id,
                        ts=datetime(2026, 11, 9, 12, 0),
                        caller_id="svc-scanner",
                        operation="vendor.op",
                        status="succeeded",
                        detail_json={"index": 0},
                    )
            rows = await _read_rows(app, tenant_id)
            return str(empty_detail.value), str(naive_ts.value), len(rows)
        finally:
            await owner.dispose()
            await app.dispose()

    empty_message, naive_message, stored = asyncio.run(scenario())

    assert "purge marker" in empty_message
    assert "timezone-aware" in naive_message
    assert stored == 0


def test_app_role_cannot_update_audit_rows(
    owner_database_url: str, app_database_url: str
) -> None:
    async def scenario() -> str:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = await _insert_tenant(owner)
            await _append_records(app, tenant_id, 1)
            with pytest.raises(DBAPIError):
                async with session_scope(tenant_id, engine=app) as session:
                    await session.execute(
                        text(
                            "UPDATE audit_record SET caller_id = 'forged' "
                            "WHERE tenant_id = :tenant_id"
                        ),
                        {"tenant_id": tenant_id},
                    )
            rows = await _read_rows(app, tenant_id)
            return rows[0].caller_id
        finally:
            await owner.dispose()
            await app.dispose()

    assert asyncio.run(scenario()) == "svc-scanner"
