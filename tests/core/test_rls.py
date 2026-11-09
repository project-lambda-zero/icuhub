"""Row-level security enforced for the application role (icuhub_app)."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from icuhub.core import audit
from icuhub.storage.db import admin_session, create_engine, session_scope

pytestmark = pytest.mark.usefixtures("clean_database")


@asynccontextmanager
async def _engine(url: str) -> AsyncGenerator[AsyncEngine]:
    engine = create_engine(url)
    try:
        yield engine
    finally:
        await engine.dispose()


async def _seed_tenants(owner_url: str, *tenants: tuple[uuid.UUID, str]) -> None:
    async with _engine(owner_url) as engine, engine.begin() as connection:
        for tenant_id, slug in tenants:
            await connection.execute(
                text("INSERT INTO tenant (id, slug, display_name) VALUES (:id, :slug, :name)"),
                {"id": tenant_id, "slug": slug, "name": slug},
            )


async def _append(engine: AsyncEngine, tenant_id: uuid.UUID, operation: str) -> None:
    async with session_scope(tenant_id, engine=engine) as session:
        await audit.append(
            session,
            tenant_id,
            ts=datetime.now(UTC),
            caller_id="rls-test",
            operation=operation,
            status="ok",
            detail_json={"operation": operation},
        )


async def _visible_operations(engine: AsyncEngine, tenant_id: uuid.UUID | None) -> list[str]:
    if tenant_id is None:
        async with admin_session(engine=engine) as session:
            result = await session.execute(text("SELECT operation FROM audit_record ORDER BY seq"))
            return list(result.scalars())
    async with session_scope(tenant_id, engine=engine) as session:
        result = await session.execute(text("SELECT operation FROM audit_record ORDER BY seq"))
        return list(result.scalars())


async def _visible_tenant_slugs(engine: AsyncEngine, tenant_id: uuid.UUID) -> list[str]:
    async with session_scope(tenant_id, engine=engine) as session:
        result = await session.execute(text("SELECT slug FROM tenant ORDER BY slug"))
        return list(result.scalars())


def test_tenant_sees_only_its_own_rows(owner_database_url: str, app_database_url: str) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()

    async def scenario() -> None:
        await _seed_tenants(owner_database_url, (tenant_a, "rls-a"), (tenant_b, "rls-b"))
        async with _engine(app_database_url) as app:
            await _append(app, tenant_a, "op-a")
            await _append(app, tenant_b, "op-b")
            assert await _visible_operations(app, tenant_a) == ["op-a"]
            assert await _visible_operations(app, tenant_b) == ["op-b"]

    asyncio.run(scenario())


def test_insert_for_another_tenant_is_rejected(owner_database_url: str, app_database_url: str) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()

    async def scenario() -> None:
        await _seed_tenants(owner_database_url, (tenant_a, "rls-a"), (tenant_b, "rls-b"))
        async with _engine(app_database_url) as app:
            with pytest.raises(DBAPIError):
                # Context is tenant A, but the row claims tenant B: WITH CHECK must reject it.
                async with session_scope(tenant_a, engine=app) as session:
                    await audit.append(
                        session,
                        tenant_b,
                        ts=datetime.now(UTC),
                        caller_id="rls-test",
                        operation="cross-tenant",
                        status="ok",
                        detail_json={"operation": "cross-tenant"},
                    )
            assert await _visible_operations(app, tenant_b) == []

    asyncio.run(scenario())


def test_unset_tenant_sees_no_rows(owner_database_url: str, app_database_url: str) -> None:
    tenant_a = uuid.uuid4()

    async def scenario() -> None:
        await _seed_tenants(owner_database_url, (tenant_a, "rls-a"))
        async with _engine(app_database_url) as app:
            await _append(app, tenant_a, "op-a")
            assert await _visible_operations(app, None) == []

    asyncio.run(scenario())


def test_tenant_table_is_visible_only_for_its_own_id(owner_database_url: str, app_database_url: str) -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()

    async def scenario() -> None:
        await _seed_tenants(owner_database_url, (tenant_a, "rls-a"), (tenant_b, "rls-b"))
        async with _engine(app_database_url) as app:
            assert await _visible_tenant_slugs(app, tenant_a) == ["rls-a"]
            assert await _visible_tenant_slugs(app, tenant_b) == ["rls-b"]

    asyncio.run(scenario())
