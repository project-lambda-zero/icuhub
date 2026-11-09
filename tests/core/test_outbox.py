"""Behaviour of transactional outbox insertion and deterministic outbox event IDs."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from icuhub.core.outbox import UnknownTenantError, add_event, outbox_event_id
from icuhub.storage.db import admin_session, create_engine, session_scope
from icuhub.storage.models import OutboxEvent, Tenant
from icuhub_schemas.events import CloudEvent


def _event(**overrides: Any) -> CloudEvent:
    fields: dict[str, Any] = {
        "id": "caller-1",
        "source": "icuhub://connector/semgrep",
        "type": "icuhub.finding.upserted",
        "time": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        "subject": "findings/f-1",
        "data": {"fingerprint": "abc", "severity": "high"},
    }
    fields.update(overrides)
    return CloudEvent(**fields)


@asynccontextmanager
async def _engine_pair(owner_url: str, app_url: str) -> AsyncGenerator[tuple[AsyncEngine, AsyncEngine]]:
    owner = create_engine(owner_url)
    app = create_engine(app_url)
    try:
        yield owner, app
    finally:
        await owner.dispose()
        await app.dispose()


async def _seed_tenant(owner: AsyncEngine, tenant_id: uuid.UUID, slug: str) -> None:
    async with admin_session(engine=owner) as session:
        session.add(Tenant(id=tenant_id, slug=slug, display_name=slug.title()))


async def _outbox_rows(owner: AsyncEngine) -> list[dict[str, Any]]:
    async with admin_session(engine=owner) as session:
        result = await session.execute(
            select(
                OutboxEvent.event_id,
                OutboxEvent.tenant_id,
                OutboxEvent.topic,
                OutboxEvent.event_json,
                OutboxEvent.relayed_at,
                OutboxEvent.attempts,
            ).order_by(OutboxEvent.created_at, OutboxEvent.id)
        )
        return [dict(row) for row in result.mappings().all()]


def test_derived_id_is_stable_under_retry_and_key_order() -> None:
    tenant_id = uuid.uuid4()
    original = _event()
    retry = _event(id="caller-2", time=datetime(2031, 6, 7, 8, 9, 10, tzinfo=UTC), correlationid="run-9")
    reordered = _event(data={"severity": "high", "fingerprint": "abc"})

    assert outbox_event_id(tenant_id, retry) == outbox_event_id(tenant_id, original)
    assert outbox_event_id(tenant_id, reordered) == outbox_event_id(tenant_id, original)


def test_derived_id_changes_on_identity_or_revision_change() -> None:
    tenant_id = uuid.uuid4()
    base = outbox_event_id(tenant_id, _event())

    assert outbox_event_id(tenant_id, _event(subject="findings/f-2")) != base
    assert outbox_event_id(tenant_id, _event(source="icuhub://connector/other")) != base
    assert outbox_event_id(tenant_id, _event(type="icuhub.finding.created")) != base
    assert outbox_event_id(tenant_id, _event(data={"fingerprint": "abc", "severity": "low"})) != base
    assert outbox_event_id(uuid.uuid4(), _event()) != base


@pytest.mark.usefixtures("clean_database")
def test_retry_converges_on_one_outbox_row(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            await _seed_tenant(owner, tenant_id, "acme")
            async with session_scope(tenant_id, engine=app) as session:
                first = await add_event(session, tenant_id, _event())
                first_id = first.event_id
            async with session_scope(tenant_id, engine=app) as session:
                retried = await add_event(session, tenant_id, _event(id="caller-2"))
                retried_id = retried.event_id

            rows = await _outbox_rows(owner)

        assert retried_id == first_id
        assert len(rows) == 1

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_persisted_row_carries_topic_payload_and_event_id(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            await _seed_tenant(owner, tenant_id, "acme")
            async with session_scope(tenant_id, engine=app) as session:
                row = await add_event(session, tenant_id, _event(correlationid="run-9"))
                event_id = row.event_id

            (stored,) = await _outbox_rows(owner)

        assert stored["event_id"] == event_id
        assert stored["tenant_id"] == tenant_id
        assert stored["topic"] == "icuhub.acme.finding.upserted"
        assert stored["relayed_at"] is None
        assert stored["attempts"] == 0
        restored = CloudEvent.model_validate(stored["event_json"])
        assert restored.id == event_id
        assert restored.correlationid == "run-9"
        assert restored.data == {"fingerprint": "abc", "severity": "high"}
        assert "tenantid" not in stored["event_json"]

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_rolled_back_transaction_leaves_no_outbox_row(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            await _seed_tenant(owner, tenant_id, "acme")
            with pytest.raises(RuntimeError, match="state change failed"):
                async with session_scope(tenant_id, engine=app) as session:
                    await add_event(session, tenant_id, _event())
                    raise RuntimeError("state change failed")

            rows = await _outbox_rows(owner)

        assert rows == []

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_unknown_tenant_is_rejected(owner_database_url: str, app_database_url: str) -> None:
    async def scenario() -> None:
        tenant_id = uuid.uuid4()
        async with _engine_pair(owner_database_url, app_database_url) as (owner, app):
            with pytest.raises(UnknownTenantError):
                async with session_scope(tenant_id, engine=app) as session:
                    await add_event(session, tenant_id, _event())

            rows = await _outbox_rows(owner)

        assert rows == []

    asyncio.run(scenario())
