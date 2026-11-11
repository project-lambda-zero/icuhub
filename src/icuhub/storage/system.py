"""Typed wrappers for the cross-tenant system functions installed by migration 0003."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from icuhub.storage.db import admin_session

__all__ = [
    "DueStreamState",
    "ServiceAccountRow",
    "WebhookEndpointRow",
    "due_stream_states",
    "lookup_webhook_endpoint",
    "service_account_by_prefix",
    "service_account_by_subject",
]


@dataclass(frozen=True)
class DueStreamState:
    id: uuid.UUID
    tenant_id: uuid.UUID
    connection_id: uuid.UUID
    target_id: uuid.UUID | None
    stream: str
    partition: str


@dataclass(frozen=True)
class WebhookEndpointRow:
    tenant_id: uuid.UUID
    connection_id: uuid.UUID
    secret_ref: str
    previous_secret_ref: str | None
    previous_valid_until: datetime | None
    disabled_at: datetime | None


@dataclass(frozen=True)
class ServiceAccountRow:
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    key_hash: str | None
    roles: tuple[str, ...]
    groups: tuple[str, ...]
    disabled_at: datetime | None


async def _rows(session: AsyncSession, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    result = await session.execute(text(sql), params)
    return [dict(row) for row in result.mappings().all()]


async def due_stream_states(
    now: datetime | None = None, limit: int = 100, *, engine: AsyncEngine | None = None
) -> list[DueStreamState]:
    async with admin_session(engine=engine) as session:
        rows = await _rows(
            session,
            "SELECT * FROM icuhub_due_stream_states(:now, :limit)",
            {"now": now or datetime.now(UTC), "limit": limit},
        )
    return [DueStreamState(id=r["id"], tenant_id=r["tenant_id"], connection_id=r["connection_id"],
                           target_id=r["target_id"], stream=r["stream"], partition=r["partition_key"]) for r in rows]


async def lookup_webhook_endpoint(
    endpoint_id: str, *, session: AsyncSession | None = None, engine: AsyncEngine | None = None
) -> WebhookEndpointRow | None:
    sql = "SELECT * FROM icuhub_webhook_endpoint_lookup(:id)"
    params = {"id": endpoint_id}
    if session is not None:
        rows = await _rows(session, sql, params)
    else:
        async with admin_session(engine=engine) as admin:
            rows = await _rows(admin, sql, params)
    return WebhookEndpointRow(**rows[0]) if rows else None


def _account(row: dict[str, Any]) -> ServiceAccountRow:
    return ServiceAccountRow(
        id=row["id"],
        tenant_id=row["tenant_id"],
        name=row["name"],
        key_hash=row["key_hash"],
        roles=tuple(row["roles"] or ()),
        groups=tuple(row["groups"] or ()),
        disabled_at=row["disabled_at"],
    )


async def service_account_by_prefix(
    prefix: str, *, engine: AsyncEngine | None = None
) -> ServiceAccountRow | None:
    async with admin_session(engine=engine) as session:
        rows = await _rows(session, "SELECT * FROM icuhub_service_account_by_prefix(:p)", {"p": prefix})
    return _account(rows[0]) if rows else None


async def service_account_by_subject(
    issuer: str, subject: str, *, engine: AsyncEngine | None = None
) -> ServiceAccountRow | None:
    async with admin_session(engine=engine) as session:
        rows = await _rows(
            session,
            "SELECT * FROM icuhub_service_account_by_subject(:i, :s)",
            {"i": issuer, "s": subject},
        )
    return _account(rows[0]) if rows else None
