"""Read and decision routes: findings, approvals, policy rules, audit.

These resources have no core service function, so queries are direct and tenant-scoped
by the session. Approval visibility is limited to the caller's groups. Decisions go
through ``core.actions.decide``, which enforces separation of duties.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.api.auth import require_roles
from icuhub.api.problems import ProblemError
from icuhub.api.rest.deps import CallerDep, TenantSession, parse_uuid
from icuhub.core.actions import decide
from icuhub.core.auth_types import Caller
from icuhub.core.evidence_export import EvidenceExportError, export_evidence_bundle
from icuhub.storage.models import Approval, AuditRecord, CorrelationCase, Finding, PolicyRule

__all__ = ["router"]

router = APIRouter(prefix="/v1", tags=["resources"])

_PAGE_MAX = 500


@router.get("/cases/{case_id}/evidence-export")
async def export_case_evidence(
    case_id: str,
    caller: Caller = Depends(require_roles("auditor")),
    session: AsyncSession = TenantSession,
) -> dict[str, Any]:
    parsed_id = parse_uuid(case_id)
    case = (
        await session.execute(
            select(CorrelationCase).where(
                CorrelationCase.id == parsed_id,
                CorrelationCase.tenant_id == caller.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if case is None:
        raise ProblemError(404, "case-not-found", "Case not found", "case evidence is unavailable")
    try:
        return await export_evidence_bundle(session, caller, parsed_id)
    except EvidenceExportError as exc:
        raise ProblemError(503, "evidence-export-unavailable", "Evidence export unavailable", str(exc)) from exc


class FindingOut(BaseModel):
    id: str
    connection_id: str
    stream: str
    status: str
    title: str | None
    severity_id: int
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None


@router.get("/findings")
async def list_findings(
    connection_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=_PAGE_MAX),
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
) -> list[FindingOut]:
    stmt = select(Finding).where(Finding.tenant_id == caller.tenant_id)
    if connection_id is not None:
        stmt = stmt.where(Finding.connection_id == parse_uuid(connection_id))
    if status is not None:
        stmt = stmt.where(Finding.status == status)
    rows = (await session.scalars(stmt.order_by(Finding.last_seen.desc()).limit(limit))).all()
    return [
        FindingOut(
            id=str(row.id),
            connection_id=str(row.connection_id),
            stream=row.stream,
            status=row.status,
            title=row.title,
            severity_id=row.severity_id,
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            resolved_at=row.resolved_at,
        )
        for row in rows
    ]


class ApprovalOut(BaseModel):
    id: str
    action_request_id: str
    approver_group: str | None
    expires_at: datetime
    decision: str | None
    created_at: datetime


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "rejected"]
    reason: str | None = Field(default=None, max_length=2000)
    change_ref: str | None = Field(default=None, max_length=500)


@router.get("/approvals")
async def list_approvals(
    limit: int = Query(default=100, ge=1, le=_PAGE_MAX),
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
) -> list[ApprovalOut]:
    """Pending approvals routed to a group the caller belongs to, plus ungrouped ones."""
    stmt = (
        select(Approval)
        .where(
            Approval.tenant_id == caller.tenant_id,
            Approval.decision.is_(None),
            Approval.approver_group.is_(None) | Approval.approver_group.in_(sorted(caller.groups)),
        )
        .order_by(Approval.created_at.desc())
        .limit(limit)
    )
    rows = (await session.scalars(stmt)).all()
    return [
        ApprovalOut(
            id=str(row.id),
            action_request_id=str(row.action_request_id),
            approver_group=row.approver_group,
            expires_at=row.expires_at,
            decision=row.decision,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post("/approvals/{approval_id}/decision")
async def decide_approval(
    approval_id: str,
    body: DecisionBody,
    caller: Caller = CallerDep,
    session: AsyncSession = TenantSession,
) -> dict[str, Any]:
    request = await decide(
        session,
        caller,
        parse_uuid(approval_id),
        body.decision,
        reason=body.reason,
        change_ref=body.change_ref,
    )
    return {"action_id": str(request.id), "state": request.state}


class PolicyRuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: int = Field(ge=0, le=100000)
    name: str = Field(min_length=1, max_length=200)
    match_json: dict[str, Any]
    decision: Literal["allow", "deny", "require_approval", "preview"]
    auto_execute_enabled: bool = False
    approver_group: str | None = Field(default=None, max_length=200)
    approval_ttl_s: int = Field(default=86400, ge=60, le=2592000)


class PolicyRuleOut(PolicyRuleIn):
    id: str


def _policy_out(row: PolicyRule) -> PolicyRuleOut:
    return PolicyRuleOut(
        id=str(row.id),
        priority=row.priority,
        name=row.name,
        match_json=row.match_json,
        decision=row.decision,  # type: ignore[arg-type]  # validated on write
        auto_execute_enabled=row.auto_execute_enabled,
        approver_group=row.approver_group,
        approval_ttl_s=row.approval_ttl_s,
    )


@router.get("/policy/rules")
async def list_rules(caller: Caller = CallerDep, session: AsyncSession = TenantSession) -> list[PolicyRuleOut]:
    rows = (
        await session.scalars(
            select(PolicyRule)
            .where(PolicyRule.tenant_id == caller.tenant_id)
            .order_by(PolicyRule.priority, PolicyRule.name)
        )
    ).all()
    return [_policy_out(row) for row in rows]


@router.post("/policy/rules", status_code=201)
async def create_rule(
    body: PolicyRuleIn,
    caller: Caller = Depends(require_roles("policy-admin")),
    session: AsyncSession = TenantSession,
) -> PolicyRuleOut:
    row = PolicyRule(
        id=uuid.uuid4(),
        tenant_id=caller.tenant_id,
        priority=body.priority,
        name=body.name,
        match_json=body.match_json,
        decision=body.decision,
        auto_execute_enabled=body.auto_execute_enabled,
        approver_group=body.approver_group,
        approval_ttl_s=body.approval_ttl_s,
    )
    session.add(row)
    await session.flush()
    return _policy_out(row)


@router.delete("/policy/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    caller: Caller = Depends(require_roles("policy-admin")),
    session: AsyncSession = TenantSession,
) -> None:
    row = await session.get(PolicyRule, parse_uuid(rule_id))
    if row is None or row.tenant_id != caller.tenant_id:
        raise ProblemError(404, "not-found", "Not found", "policy rule not found")
    await session.delete(row)


class AuditOut(BaseModel):
    seq: int
    ts: datetime
    caller_id: str
    connection_id: str | None
    operation: str
    classification: str | None
    decision: str | None
    status: str
    correlation_id: str | None


@router.get("/audit")
async def list_audit(
    limit: int = Query(default=100, ge=1, le=_PAGE_MAX),
    after_seq: int | None = Query(default=None, ge=0),
    caller: Caller = Depends(require_roles("auditor", "operator")),
    session: AsyncSession = TenantSession,
) -> list[AuditOut]:
    stmt = select(AuditRecord).where(AuditRecord.tenant_id == caller.tenant_id)
    if after_seq is not None:
        stmt = stmt.where(AuditRecord.seq > after_seq)
    rows = (await session.scalars(stmt.order_by(AuditRecord.seq).limit(limit))).all()
    return [
        AuditOut(
            seq=row.seq,
            ts=row.ts,
            caller_id=row.caller_id,
            connection_id=str(row.connection_id) if row.connection_id else None,
            operation=row.operation,
            classification=row.classification,
            decision=row.decision,
            status=row.status,
            correlation_id=row.correlation_id,
        )
        for row in rows
    ]
