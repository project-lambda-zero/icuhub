"""Connection routes: lifecycle, credential rotation, health, and operation/action dispatch."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Header
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.api.problems import ProblemError
from icuhub.api.rest.deps import (
    CallerDep,
    ConnectorRegistry,
    CorrelationHeader,
    IdempotencyHeader,
    ServicesDep,
    TenantSession,
    connector_registry,
    parse_uuid,
    require_correlation,
    require_idempotency,
)
from icuhub.core.actions import submit_action
from icuhub.core.auth_types import Caller
from icuhub.core.connections import (
    create_connection,
    delete_connection,
    get_connection,
    list_connections,
    rotate_secret,
    update_connection,
)
from icuhub.core.services import Services
from icuhub.storage.models import Connection

__all__ = ["router"]

router = APIRouter(prefix="/v1/connections", tags=["connections"])


class ConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(min_length=1, max_length=64)
    slug: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=200)
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    egress_class: str = "vendor_tenant"
    allowed_operations: list[str] | None = None


class ConnectionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    config: dict[str, Any] | None = None
    secrets: dict[str, str] | None = None
    allowed_operations: list[str] | None = None
    status: Literal["active", "paused", "disabled"] | None = None


class SecretRotation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)


class ConnectionOut(BaseModel):
    id: str
    kind: str
    slug: str
    display_name: str
    status: str
    allowed_operations: list[str] | None

    @classmethod
    def of(cls, row: Connection) -> ConnectionOut:
        return cls(
            id=str(row.id),
            kind=row.kind,
            slug=row.slug,
            display_name=row.display_name,
            status=row.status,
            allowed_operations=row.allowed_operations,
        )


def _kind_class(registry: ConnectorRegistry, kind: str) -> type:
    cls = registry.get(kind)
    if cls is None:
        raise ProblemError(404, "not-found", "Not found", "connector kind not registered")
    return cls


@router.get("")
async def list_all(
    caller: Caller = CallerDep, session: AsyncSession = TenantSession
) -> list[ConnectionOut]:
    rows = await list_connections(session, caller.tenant_id)
    return [ConnectionOut.of(row) for row in rows]


@router.post("", status_code=201)
async def create(
    body: ConnectionCreate,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
    services: Services = ServicesDep,
) -> ConnectionOut:
    row = await create_connection(
        session,
        caller.tenant_id,
        kind=body.kind,
        slug=body.slug,
        display_name=body.display_name,
        config=body.config,
        secrets=body.secrets,
        caller=caller,
        registry=connector_registry(),
        broker=services.broker,
        egress_class=body.egress_class,
        allowed_operations=body.allowed_operations,
    )
    return ConnectionOut.of(row)


@router.get("/{connection_id}")
async def read(
    connection_id: str, caller: Caller = CallerDep, session: AsyncSession = TenantSession
) -> ConnectionOut:
    row = await get_connection(session, caller.tenant_id, parse_uuid(connection_id))
    return ConnectionOut.of(row)


@router.patch("/{connection_id}")
async def update(
    connection_id: str,
    body: ConnectionUpdate,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
    services: Services = ServicesDep,
) -> ConnectionOut:
    row = await update_connection(
        session,
        caller,
        parse_uuid(connection_id),
        registry=connector_registry(),
        broker=services.broker,
        display_name=body.display_name,
        config=body.config,
        secrets=body.secrets,
        allowed_operations=body.allowed_operations,
        status=body.status,
    )
    return ConnectionOut.of(row)


@router.delete("/{connection_id}", status_code=204)
async def delete(
    connection_id: str,
    force: bool = False,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
) -> None:
    await delete_connection(session, caller, parse_uuid(connection_id), force=force)


@router.put("/{connection_id}/secrets/{field}", status_code=204)
async def rotate(
    connection_id: str,
    field: str,
    body: SecretRotation,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
    services: Services = ServicesDep,
) -> None:
    await rotate_secret(
        session,
        caller,
        parse_uuid(connection_id),
        field,
        body.value,
        registry=connector_registry(),
        broker=services.broker,
    )


@router.post("/{connection_id}/health")
async def health(
    connection_id: str,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
    services: Services = ServicesDep,
) -> dict[str, Any]:
    report = await services.runtime.check_connection(session, caller, parse_uuid(connection_id))
    return report.model_dump(mode="json")


class OperationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    args: dict[str, Any] = Field(default_factory=dict)


@router.post("/{connection_id}/operations/{name}")
async def dispatch(
    connection_id: str,
    name: str,
    body: OperationBody,
    mode: Literal["live", "replay"] = Header(default="live", alias="X-ICUHUB-Mode"),
    correlation_id: str | None = CorrelationHeader,
    idempotency_key: str | None = IdempotencyHeader,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
    services: Services = ServicesDep,
) -> dict[str, Any]:
    """Route a named operation (read) or action (write) on a connection.

    Reads go through ``ConnectorRuntime.run_operation``. Writes go through
    ``submit_action`` and require ``Idempotency-Key``. Both require ``X-Correlation-Id``.
    """
    cid = require_correlation(correlation_id)
    row = await get_connection(session, caller.tenant_id, parse_uuid(connection_id))
    cls = _kind_class(connector_registry(), row.kind)
    if name in cls.operations():
        result = await services.runtime.run_operation(session, caller, row.id, name, body.args)
        return {"result": result}
    if name in cls.actions():
        key = require_idempotency(idempotency_key)
        request = await submit_action(
            session,
            caller,
            row.id,
            name,
            body.args,
            idempotency_key=key,
            correlation_id=cid,
            mode=mode,
        )
        return {
            "action_id": str(request.id),
            "state": request.state,
            "correlation_id": cid,
        }
    raise ProblemError(404, "not-found", "Not found", "connector has no such operation or action")
