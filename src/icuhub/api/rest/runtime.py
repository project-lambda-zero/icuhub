"""Runtime routes: connector catalog, operations, actions, sync, reports, routes, audit verify.

Spec: HLD section "REST surface" (lines 574-590). Report upload uses a raw
octet-stream body so no multipart dependency is required.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.api.auth import require_roles
from icuhub.api.problems import ProblemError
from icuhub.api.rest.deps import (
    CallerDep,
    ServicesDep,
    TenantSession,
    connector_registry,
    parse_uuid,
)
from icuhub.core.actions import decide
from icuhub.core.audit import verify_chain
from icuhub.core.auth_types import Caller
from icuhub.core.connections import get_connection, rotate_secret
from icuhub.core.policy import PolicyInput, evaluate
from icuhub.core.services import Services
from icuhub.core.sync import submit_import, trigger_sync
from icuhub.core.webhooks import create_endpoint, rotate_endpoint
from icuhub.storage.models import ActionRequest, PolicyRule, TicketRoute

__all__ = ["router"]

router = APIRouter(prefix="/v1", tags=["runtime"])
_MAX_REPORT_BYTES = 64 * 1024 * 1024


@router.get("/connectors")
async def catalog(caller: Caller = CallerDep) -> list[dict[str, Any]]:
    return [
        {
            "kind": cls.kind,
            "capabilities": sorted(cls.capabilities),
            "streams": sorted(cls.streams()),
            "operations": {name: spec.classification for name, spec in cls.operations().items()},
            "actions": {name: spec.classification for name, spec in cls.actions().items()},
            "importers": sorted(cls.importers()),
            "webhooks": sorted(cls.webhooks()),
        }
        for _, cls in sorted(connector_registry().items())
    ]


@router.get("/connections/{connection_id}/operations")
async def available_operations(
    connection_id: str, caller: Caller = CallerDep, session: AsyncSession = TenantSession
) -> list[dict[str, Any]]:
    row = await get_connection(session, caller.tenant_id, parse_uuid(connection_id))
    cls = connector_registry().get(row.kind)
    if cls is None:
        raise ProblemError(404, "not-found", "Not found", "unknown connector kind")
    rules = list((await session.scalars(select(PolicyRule).where(PolicyRule.tenant_id == caller.tenant_id))).all())
    out: list[dict[str, Any]] = []
    for surface, specs in (("operation", cls.operations()), ("action", cls.actions())):
        for name, spec in sorted(specs.items()):
            if row.allowed_operations is not None and name not in row.allowed_operations:
                continue
            decision = evaluate(
                rules,
                PolicyInput(
                    caller=caller,
                    connection_id=row.id,
                    connection_kind=row.kind,
                    operation=name,
                    classification=spec.classification,  # type: ignore[arg-type]
                    args={},
                ),
            )
            if decision.decision != "deny":
                out.append(
                    {
                        "name": name,
                        "surface": surface,
                        "classification": spec.classification,
                        "decision": decision.decision,
                    }
                )
    return out


@router.get("/actions/{action_id}")
async def action_state(
    action_id: str, caller: Caller = CallerDep, session: AsyncSession = TenantSession
) -> dict[str, Any]:
    row = await session.get(ActionRequest, parse_uuid(action_id))
    if row is None or row.tenant_id != caller.tenant_id:
        raise ProblemError(404, "not-found", "Not found", "action not found")
    return {
        "id": str(row.id),
        "connection_id": str(row.connection_id),
        "action": row.action,
        "state": row.state,
        "classification": row.classification,
        "decision": row.decision,
        "args_digest": row.args_digest,
        "result": row.result_json,
        "error_class": row.error_class,
        "correlation_id": row.correlation_id,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


class SyncBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stream: str
    mode: Literal["incremental", "full", "targeted"] = "incremental"
    target_id: str | None = None


@router.post("/connections/{connection_id}/sync", status_code=202)
async def sync_now(
    connection_id: str,
    body: SyncBody,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
    services: Services = ServicesDep,
) -> dict[str, Any]:
    row = await get_connection(session, caller.tenant_id, parse_uuid(connection_id))
    cls = services.runtime._class(row)
    if body.stream not in cls.streams():
        raise ProblemError(404, "not-found", "Not found", f"{row.kind} has no stream {body.stream!r}")
    try:
        job_id = await trigger_sync(
            session,
            caller,
            row.id,
            body.stream,
            mode=body.mode,
            target_id=parse_uuid(body.target_id) if body.target_id else None,
        )
    except ValueError as exc:
        raise ProblemError(422, "validation", "Validation failed", str(exc)) from exc
    return {"job_id": str(job_id), "state": "queued"}


@router.post("/connections/{connection_id}/reports", status_code=202)
async def upload_report(
    connection_id: str,
    request: Request,
    importer: str = Query(...),
    filename: str = Query(default="report.bin"),
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
) -> dict[str, Any]:
    data = await request.body()
    if not data:
        raise ProblemError(400, "empty-report", "Empty report", "request body must contain the report bytes")
    if len(data) > _MAX_REPORT_BYTES:
        raise ProblemError(413, "report-too-large", "Report too large", f"limit is {_MAX_REPORT_BYTES} bytes")
    record = await submit_import(session, caller, parse_uuid(connection_id), importer, filename, data)
    return {"import_id": str(record.id), "state": record.state, "digest": record.digest}


@router.get("/audit/verify")
async def audit_verify(
    caller: Caller = Depends(require_roles("auditor")), session: AsyncSession = TenantSession
) -> dict[str, Any]:
    result = await verify_chain(session, caller.tenant_id)
    return {"ok": result.ok, "checked": result.checked, "failures": [asdict(f) for f in result.failures]}


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=2000)
    change_ref: str | None = Field(default=None, max_length=200)


async def _decide(
    approval_id: str,
    decision: Literal["approved", "rejected"],
    body: DecisionBody,
    caller: Caller,
    session: AsyncSession,
) -> dict[str, Any]:
    request = await decide(
        session, caller, parse_uuid(approval_id), decision, reason=body.reason, change_ref=body.change_ref
    )
    return {"action_id": str(request.id), "state": request.state}


@router.post("/approvals/{approval_id}/approve")
async def approve(
    approval_id: str, body: DecisionBody, caller: Caller = CallerDep, session: AsyncSession = TenantSession
) -> dict[str, Any]:
    return await _decide(approval_id, "approved", body, caller, session)


@router.post("/approvals/{approval_id}/reject")
async def reject(
    approval_id: str, body: DecisionBody, caller: Caller = CallerDep, session: AsyncSession = TenantSession
) -> dict[str, Any]:
    return await _decide(approval_id, "rejected", body, caller, session)


class RulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: int | None = None
    name: str | None = None
    match: dict[str, Any] | None = None
    decision: Literal["allow", "deny", "require_approval"] | None = None
    approver_group: str | None = None
    approval_ttl_s: int | None = Field(default=None, ge=60)
    auto_execute_enabled: bool | None = None


@router.patch("/policy/rules/{rule_id}")
async def patch_rule(
    rule_id: str,
    body: RulePatch,
    caller: Caller = Depends(require_roles("policy-admin")),
    session: AsyncSession = TenantSession,
) -> dict[str, Any]:
    rule = await session.get(PolicyRule, parse_uuid(rule_id))
    if rule is None or rule.tenant_id != caller.tenant_id:
        raise ProblemError(404, "not-found", "Not found", "rule not found")
    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        column = "match_json" if key == "match" else key
        setattr(rule, column, value)
    await session.flush()
    return {"id": str(rule.id), "updated": sorted(changes)}


class RouteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    connection_id: str
    action: str = "create_issue"
    enabled: bool = True
    match: dict[str, Any] = Field(default_factory=dict)
    template: dict[str, Any] = Field(default_factory=dict)
    status_policy: dict[str, Any] = Field(default_factory=dict)


class RoutePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    match: dict[str, Any] | None = None
    template: dict[str, Any] | None = None
    status_policy: dict[str, Any] | None = None


def _route_out(row: TicketRoute) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "name": row.name,
        "connection_id": str(row.connection_id),
        "action": row.action,
        "enabled": row.enabled,
        "match": row.match_json,
        "template": row.template_json,
        "status_policy": row.status_policy_json,
    }


@router.get("/routes")
async def list_routes(caller: Caller = CallerDep, session: AsyncSession = TenantSession) -> list[dict[str, Any]]:
    rows = (await session.scalars(select(TicketRoute).where(TicketRoute.tenant_id == caller.tenant_id))).all()
    return [_route_out(row) for row in rows]


@router.post("/routes", status_code=201)
async def create_route(
    body: RouteBody,
    caller: Caller = Depends(require_roles("operator")),
    session: AsyncSession = TenantSession,
    services: Services = ServicesDep,
) -> dict[str, Any]:
    connection = await get_connection(session, caller.tenant_id, parse_uuid(body.connection_id))
    cls = services.runtime._class(connection)
    if body.action not in cls.actions():
        raise ProblemError(400, "unknown-action", "Unknown action", f"{connection.kind} has no action {body.action!r}")
    row = TicketRoute(
        tenant_id=caller.tenant_id,
        name=body.name,
        connection_id=connection.id,
        action=body.action,
        enabled=body.enabled,
        match_json=body.match,
        template_json=body.template,
        status_policy_json=body.status_policy,
    )
    session.add(row)
    await session.flush()
    return _route_out(row)


@router.patch("/routes/{route_id}")
async def patch_route(
    route_id: str,
    body: RoutePatch,
    caller: Caller = Depends(require_roles("operator")),
    session: AsyncSession = TenantSession,
) -> dict[str, Any]:
    row = await session.get(TicketRoute, parse_uuid(route_id))
    if row is None or row.tenant_id != caller.tenant_id:
        raise ProblemError(404, "not-found", "Not found", "route not found")
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(row, {"match": "match_json", "template": "template_json", "status_policy": "status_policy_json"}.get(key, key), value)
    await session.flush()
    return _route_out(row)


@router.delete("/routes/{route_id}", status_code=204)
async def delete_route(
    route_id: str,
    caller: Caller = Depends(require_roles("operator")),
    session: AsyncSession = TenantSession,
) -> None:
    row = await session.get(TicketRoute, parse_uuid(route_id))
    if row is None or row.tenant_id != caller.tenant_id:
        raise ProblemError(404, "not-found", "Not found", "route not found")
    await session.delete(row)


@router.post("/connections/{connection_id}/webhooks", status_code=201)
async def webhook_create(
    connection_id: str,
    caller: Caller = Depends(require_roles("operator")),
    session: AsyncSession = TenantSession,
) -> dict[str, Any]:
    endpoint_id, secret = await create_endpoint(session, caller, parse_uuid(connection_id))
    return {"endpoint_id": endpoint_id, "secret": secret, "url": f"/hooks/{endpoint_id}"}


@router.post("/webhooks/{endpoint_id}/rotate")
async def webhook_rotate(
    endpoint_id: str,
    caller: Caller = Depends(require_roles("operator")),
    session: AsyncSession = TenantSession,
) -> dict[str, Any]:
    secret = await rotate_endpoint(session, caller, endpoint_id)
    return {"endpoint_id": endpoint_id, "secret": secret}


class CredentialBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1)
    value: str = Field(min_length=1)


@router.put("/connections/{connection_id}/credential", status_code=204)
async def write_credential(
    connection_id: str,
    body: CredentialBody,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
    services: Services = ServicesDep,
) -> None:
    await rotate_secret(
        session,
        caller,
        parse_uuid(connection_id),
        body.field,
        body.value,
        registry=connector_registry(),
        broker=services.broker,
    )
