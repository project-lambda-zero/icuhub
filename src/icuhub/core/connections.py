"""Connection lifecycle: configuration validation, secret storage, audited mutations."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, get_args, get_origin

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.audit import append as audit_append
from icuhub.core.auth_types import Caller
from icuhub.core.credentials import CredentialBroker
from icuhub.kit.connector import Connector
from icuhub.kit.errors import ConfigError, NotFound
from icuhub.kit.types import SecretRef
from icuhub.storage.models import Connection, Finding

__all__ = [
    "create_connection",
    "delete_connection",
    "get_connection",
    "list_connections",
    "rotate_secret",
    "update_connection",
]


def _is_secret_annotation(annotation: Any) -> bool:
    if annotation is SecretRef:
        return True
    origin = get_origin(annotation)
    if origin is None:
        return False
    return any(_is_secret_annotation(arg) for arg in get_args(annotation))


def secret_fields(cls: type[Connector]) -> dict[str, Any]:
    """Return the config fields declared as secrets (declaration, not naming)."""
    return {
        name: field.annotation
        for name, field in cls.config_model.model_fields.items()
        if _is_secret_annotation(field.annotation)
    }


def _audit_operation(suffix: str) -> str:
    return f"connection.{suffix}"


async def _store_secrets(
    session: AsyncSession,
    broker: CredentialBroker,
    cls: type[Connector],
    tenant_id: uuid.UUID,
    config: dict[str, Any],
    secrets: dict[str, str],
) -> dict[str, Any]:
    fields = secret_fields(cls)
    unknown = set(secrets) - set(fields)
    if unknown:
        raise ConfigError(f"secrets supplied for non-secret fields: {sorted(unknown)}")
    resolved = dict(config)
    for name in fields:
        if name in secrets:
            ref = await broker.store(tenant_id, f"{cls.kind}.{name}", secrets[name].encode("utf-8"), session=session)
            resolved[name] = {"ref": ref.ref}
        elif name in resolved and isinstance(resolved[name], str):
            ref = await broker.store(tenant_id, f"{cls.kind}.{name}", resolved[name].encode("utf-8"), session=session)
            resolved[name] = {"ref": ref.ref}
    return resolved


async def create_connection(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    kind: str,
    slug: str,
    display_name: str,
    config: dict[str, Any],
    secrets: dict[str, str],
    caller: Caller,
    registry: dict[str, type[Connector]],
    broker: CredentialBroker,
    egress_class: str = "vendor_tenant",
    allowed_operations: list[str] | None = None,
) -> Connection:
    """Validate config, store secrets in the broker, and persist only references."""
    if kind not in registry:
        raise ConfigError(f"unknown connector kind {kind!r}")
    cls = registry[kind]
    resolved = await _store_secrets(session, broker, cls, tenant_id, config, secrets)
    cls.config_model.model_validate(resolved)
    connection = Connection(
        tenant_id=tenant_id,
        kind=kind,
        slug=slug,
        display_name=display_name,
        config_json=resolved,
        egress_class=egress_class,
        allowed_operations=allowed_operations,
    )
    session.add(connection)
    await session.flush()
    await audit_append(
        session,
        tenant_id,
        ts=datetime.now(UTC),
        caller_id=caller.id,
        connection_id=connection.id,
        operation=_audit_operation("create"),
        status="succeeded",
        detail_json={"kind": kind, "slug": slug},
    )
    return connection


async def get_connection(session: AsyncSession, tenant_id: uuid.UUID, connection_id: uuid.UUID) -> Connection:
    connection = await session.get(Connection, connection_id)
    if connection is None or connection.tenant_id != tenant_id:
        raise NotFound("connection not found")
    return connection


async def list_connections(session: AsyncSession, tenant_id: uuid.UUID) -> list[Connection]:
    result = await session.execute(select(Connection).where(Connection.tenant_id == tenant_id).order_by(Connection.slug))
    return list(result.scalars().all())


async def update_connection(
    session: AsyncSession,
    caller: Caller,
    connection_id: uuid.UUID,
    *,
    registry: dict[str, type[Connector]],
    broker: CredentialBroker,
    display_name: str | None = None,
    config: dict[str, Any] | None = None,
    secrets: dict[str, str] | None = None,
    allowed_operations: list[str] | None = None,
    status: str | None = None,
) -> Connection:
    connection = await get_connection(session, caller.tenant_id, connection_id)
    cls = registry[connection.kind]
    if config is not None or secrets:
        merged = dict(connection.config_json)
        merged.update(config or {})
        merged = await _store_secrets(session, broker, cls, caller.tenant_id, merged, secrets or {})
        cls.config_model.model_validate(merged)
        connection.config_json = merged
    if display_name is not None:
        connection.display_name = display_name
    if allowed_operations is not None:
        connection.allowed_operations = allowed_operations
    if status is not None:
        if status not in ("active", "degraded", "disabled"):
            raise ConfigError(f"invalid connection status {status!r}")
        connection.status = status
    connection.updated_at = datetime.now(UTC)
    await audit_append(
        session,
        caller.tenant_id,
        ts=datetime.now(UTC),
        caller_id=caller.id,
        connection_id=connection.id,
        operation=_audit_operation("update"),
        status="succeeded",
        detail_json={"fields": sorted(k for k, v in (("config", config), ("display_name", display_name), ("status", status)) if v is not None)},
    )
    return connection


async def rotate_secret(
    session: AsyncSession,
    caller: Caller,
    connection_id: uuid.UUID,
    field: str,
    value: str,
    *,
    registry: dict[str, type[Connector]],
    broker: CredentialBroker,
) -> Connection:
    """Store a new credential for one secret field; the old credential row is kept for audit."""
    connection = await get_connection(session, caller.tenant_id, connection_id)
    cls = registry[connection.kind]
    if field not in secret_fields(cls):
        raise ConfigError(f"{field!r} is not a declared secret field of {connection.kind}")
    ref = await broker.store(caller.tenant_id, f"{connection.kind}.{field}", value.encode("utf-8"), session=session)
    config = dict(connection.config_json)
    config[field] = {"ref": ref.ref}
    connection.config_json = config
    connection.updated_at = datetime.now(UTC)
    await audit_append(
        session,
        caller.tenant_id,
        ts=datetime.now(UTC),
        caller_id=caller.id,
        connection_id=connection.id,
        operation=_audit_operation("rotate_secret"),
        status="succeeded",
        detail_json={"field": field},
    )
    return connection


async def delete_connection(
    session: AsyncSession, caller: Caller, connection_id: uuid.UUID, *, force: bool = False
) -> None:
    connection = await get_connection(session, caller.tenant_id, connection_id)
    findings = await session.scalar(select(func.count(Finding.id)).where(Finding.connection_id == connection.id))
    if findings and not force:
        raise ConfigError("connection has findings; pass force=True to delete")
    await audit_append(
        session,
        caller.tenant_id,
        ts=datetime.now(UTC),
        caller_id=caller.id,
        connection_id=connection.id,
        operation=_audit_operation("delete"),
        status="succeeded",
        detail_json={"slug": connection.slug, "forced": force},
    )
    await session.delete(connection)
