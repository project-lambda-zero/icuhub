"""Connector construction and synchronous read operations with policy and audit."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from aiolimiter import AsyncLimiter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.connectors import CONNECTORS
from icuhub.core.audit import append as audit_append
from icuhub.core.auth_types import Caller
from icuhub.core.credentials import CredentialBroker
from icuhub.core.outbox import add_event
from icuhub.core.policy import PolicyInput, evaluate
from icuhub.kit.connector import Connector, build_context
from icuhub.kit.errors import ConfigError, PermissionDenied
from icuhub.kit.http import build_http
from icuhub.kit.types import HealthReport, SecretRef, Target
from icuhub.storage.models import Connection, PolicyRule
from icuhub.storage.models import Target as TargetRow

__all__ = ["ConnectorRuntime"]


class _BrokerSecrets:
    def __init__(self, broker: CredentialBroker, tenant_id: uuid.UUID, session: AsyncSession) -> None:
        self._broker = broker
        self._tenant_id = tenant_id
        self._session = session

    async def resolve(self, ref: SecretRef) -> bytes:
        return await self._broker.resolve(self._tenant_id, ref, session=self._session)


class ConnectorRuntime:
    """Opens connectors from stored connections; every vendor read passes policy and audit."""

    def __init__(
        self,
        broker: CredentialBroker,
        settings: Any,
        registry: dict[str, type[Connector]] | None = None,
        *,
        transport: Any = None,
    ) -> None:
        self._broker = broker
        self._settings = settings
        self._registry = registry if registry is not None else CONNECTORS
        self._transport = transport
        self._limiters: dict[uuid.UUID, dict[str, AsyncLimiter]] = {}

    def _class(self, connection: Connection) -> type[Connector]:
        try:
            return self._registry[connection.kind]
        except KeyError as exc:
            raise ConfigError(f"unknown connector kind {connection.kind!r}") from exc

    async def _connection(self, session: AsyncSession, tenant_id: uuid.UUID, connection_id: uuid.UUID) -> Connection:
        connection = await session.get(Connection, connection_id)
        if connection is None or connection.tenant_id != tenant_id:
            raise ConfigError("connection not found")
        return connection

    def _limiter_for(self, connection: Connection, cls: type[Connector]) -> dict[str, AsyncLimiter] | None:
        if not cls.rate_limits:
            return None
        if connection.id not in self._limiters:
            self._limiters[connection.id] = {
                pool: AsyncLimiter(rate, period) for pool, (rate, period) in cls.rate_limits.items()
            }
        return self._limiters[connection.id]

    async def open(self, session: AsyncSession, tenant_id: uuid.UUID, connection_id: uuid.UUID) -> Connector:
        """Build a connector with resolved secrets, auth, TLS, and per-connection limiters."""
        connection = await self._connection(session, tenant_id, connection_id)
        cls = self._class(connection)
        config = cls.config_model.model_validate(connection.config_json)
        ctx = build_context(
            secrets=_BrokerSecrets(self._broker, tenant_id, session),
            clock=lambda: datetime.now(UTC),
            connection_id=str(connection.id),
            tenant_id=str(tenant_id),
        )
        connector = cls(config, ctx)
        auth = await connector.build_auth()
        cert_pem = key_pem = None
        if getattr(config, "client_cert", None) is not None:
            cert_pem = await self._broker.resolve(tenant_id, config.client_cert, session=session)
        if getattr(config, "client_key", None) is not None:
            key_pem = await self._broker.resolve(tenant_id, config.client_key, session=session)
        if cls.uses_http:
            ctx.http = build_http(
                config,
                auth,
                transport=self._transport,
                limiter=self._limiter_for(connection, cls),
                extra_hosts=tuple(getattr(config, "extra_hosts", ()) or ()),
                client_cert_pem=cert_pem,
                client_key_pem=key_pem,
            )
        return connector

    async def _rules(self, session: AsyncSession, tenant_id: uuid.UUID) -> list[PolicyRule]:
        result = await session.execute(select(PolicyRule).where(PolicyRule.tenant_id == tenant_id))
        return list(result.scalars().all())

    async def run_operation(
        self, session: AsyncSession, caller: Caller, connection_id: uuid.UUID, operation: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a read operation through policy, audit, and the outbox."""
        connection = await self._connection(session, caller.tenant_id, connection_id)
        cls = self._class(connection)
        spec = cls.operations().get(operation)
        if spec is None:
            raise ConfigError(f"{connection.kind} has no operation {operation!r}")
        if connection.allowed_operations is not None and operation not in connection.allowed_operations:
            raise PermissionDenied(f"operation {operation!r} is not enabled on this connection")
        req = PolicyInput(
            caller=caller,
            connection_id=connection.id,
            connection_kind=connection.kind,
            operation=operation,
            classification=spec.classification,
            egress_class=spec.egress_class,
            args=args,
        )
        decision = evaluate(await self._rules(session, caller.tenant_id), req)
        now = datetime.now(UTC)
        if decision.decision == "deny":
            await audit_append(
                session, caller.tenant_id, ts=now, caller_id=caller.id, connection_id=connection.id,
                operation=operation, classification=spec.classification, decision="deny",
                status="denied", detail_json={"reason": decision.reason},
            )
            raise PermissionDenied(f"operation denied by policy: {decision.reason}")
        connector = await self.open(session, caller.tenant_id, connection_id)
        parsed = spec.input_model.model_validate(args)
        status = "succeeded"
        error: str | None = None
        try:
            result = await spec.fn(connector, parsed)
        except Exception as exc:
            status = "failed"
            error = type(exc).__name__
            raise
        finally:
            await audit_append(
                session, caller.tenant_id, ts=datetime.now(UTC), caller_id=caller.id, connection_id=connection.id,
                operation=operation, classification=spec.classification, decision=decision.decision,
                status=status, detail_json={"error": error} if error else {"result": "ok"},
            )
        output = result.model_dump(mode="json")
        from icuhub_schemas.events import CloudEvent  # noqa: PLC0415

        await add_event(
            session,
            caller.tenant_id,
            CloudEvent(
                id=f"op-{uuid.uuid4()}",
                source=f"icuhub://connections/{connection.id}",
                type="icuhub.operation.executed",
                subject=operation,
                time=datetime.now(UTC),
                data={"connection_id": str(connection.id), "operation": operation, "caller": caller.id},
            ),
        )
        return output

    async def check_connection(self, session: AsyncSession, caller: Caller, connection_id: uuid.UUID) -> HealthReport:
        connection = await self._connection(session, caller.tenant_id, connection_id)
        connector = await self.open(session, caller.tenant_id, connection_id)
        report = await connector.check()
        connection.last_health_at = datetime.now(UTC)
        connection.last_health_json = report.model_dump(mode="json")
        if report.status == "failing":
            connection.status = "degraded"
        elif report.status == "healthy" and connection.status == "degraded":
            connection.status = "active"
        from icuhub_schemas.events import CloudEvent  # noqa: PLC0415

        await add_event(
            session,
            caller.tenant_id,
            CloudEvent(
                id=f"health-{connection.id}-{uuid.uuid4()}",
                source=f"icuhub://connections/{connection.id}",
                type="icuhub.connection.health",
                subject=connection.slug,
                time=datetime.now(UTC),
                data={"status": report.status},
            ),
        )
        return report

    async def discover_targets(self, session: AsyncSession, caller: Caller, connection_id: uuid.UUID) -> list[TargetRow]:
        """Upsert discovered targets and age missing ones; a failed discovery changes nothing."""
        connection = await self._connection(session, caller.tenant_id, connection_id)
        connector = await self.open(session, caller.tenant_id, connection_id)
        now = datetime.now(UTC)
        existing = {
            row.source_uid: row
            for row in (await session.execute(select(TargetRow).where(TargetRow.connection_id == connection.id)))
            .scalars()
            .all()
        }
        seen: set[str] = set()
        async for record in connector.discover():
            seen.add(record.source_uid)
            row = existing.get(record.source_uid)
            if row is None:
                row = TargetRow(
                    tenant_id=caller.tenant_id,
                    connection_id=connection.id,
                    source_uid=record.source_uid,
                    kind=record.kind,
                    display_name=record.display_name,
                )
                session.add(row)
            row.display_name = record.display_name
            row.attributes_json = record.attributes
            row.last_seen_at = now
            row.missing_since = None
        for uid, row in existing.items():
            if uid not in seen and row.missing_since is None:
                row.missing_since = now
        result = await session.execute(select(TargetRow).where(TargetRow.connection_id == connection.id))
        return list(result.scalars().all())

    def target_for(self, row: TargetRow) -> Target:
        return Target(
            id=str(row.id),
            source_uid=row.source_uid,
            kind=row.kind,
            display_name=row.display_name,
            attributes=row.attributes_json or {},
        )
