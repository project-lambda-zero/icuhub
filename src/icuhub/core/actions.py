"""Action requests: policy, plan, durable approval, apply, and reconciliation (ADR-0014).

Every transition appends an audit record and an outbox event. Approval binds to the
plan hash; the initial apply re-plans and refuses a stale plan. ``accepted_async``
and ``outcome_unknown`` are resolved by the connector's reconcile hook against the
stored approved plan and persisted outcome, never by a blind retry (FR-POL-09, PA-26..28).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.audit import append as audit_append
from icuhub.core.auth_types import Caller
from icuhub.core.policy import PolicyInput, effective_outcome, evaluate
from icuhub.core.queue import Lease, LeaseLost, enqueue, heartbeat
from icuhub.core.services import get_services
from icuhub.kit.connector import ActionSpec, Connector
from icuhub.kit.errors import Conflict, NotFound, PermissionDenied, StalePlan
from icuhub.kit.types import ActionOutcome, ActionPlan
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ACTION_ACTIVE_STATES,
    ActionPlanRow,
    ActionRequest,
    Approval,
    Connection,
    CorrelationCase,
    EvidenceItem,
    PolicyRule,
    Tenant,
)
from icuhub_schemas.events import CloudEvent

_LOG = logging.getLogger("icuhub.actions")

__all__ = [
    "JOB_HANDLERS",
    "decide",
    "expire_approvals",
    "run_apply_job",
    "run_expire_job",
    "run_reconcile_job",
    "submit_action",
]

_MAX_ASYNC_POLLS = 60
_MAX_RECONCILE_ATTEMPTS = 12


def _digest(args: dict[str, Any]) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


_POST_ACTION_ASSESSMENTS = {
    ("openshift", "update_scc"): "scc_assessment_snapshot",
    ("openshift", "update_route_tls"): "route_assessment_snapshot",
}


async def _record_case_evidence(
    session: AsyncSession,
    request: ActionRequest,
    *,
    kind: str,
    ref_table: str,
    ref_id: uuid.UUID,
    digest: str,
) -> None:
    """Link one immutable action artifact to its case using the exporter's exact digest."""
    if request.correlation_id is None:
        return
    try:
        case_id = uuid.UUID(request.correlation_id)
    except ValueError:
        return
    case = await session.get(CorrelationCase, case_id)
    if case is None or case.tenant_id != request.tenant_id:
        return
    existing = (
        await session.execute(
            select(EvidenceItem).where(
                EvidenceItem.tenant_id == request.tenant_id,
                EvidenceItem.case_id == case_id,
                EvidenceItem.kind == kind,
                EvidenceItem.ref_table == ref_table,
                EvidenceItem.ref_id == ref_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.digest != digest:
            raise Conflict(f"{kind} evidence changed after it was recorded")
        return
    session.add(
        EvidenceItem(
            tenant_id=request.tenant_id,
            case_id=case_id,
            kind=kind,
            digest=digest,
            ref_table=ref_table,
            ref_id=ref_id,
        )
    )


async def _record_approval_evidence(
    session: AsyncSession, request: ActionRequest, approval: Approval
) -> None:
    from icuhub.core.evidence_export import _approval  # noqa: PLC0415
    from icuhub.core.evidence_export import _digest as export_digest  # noqa: PLC0415

    await _record_case_evidence(
        session,
        request,
        kind="approval",
        ref_table="approval",
        ref_id=approval.id,
        digest=export_digest(_approval(approval)),
    )


async def _schedule_post_action_assessment(session: AsyncSession, request: ActionRequest) -> None:
    connection = await session.get(Connection, request.connection_id)
    if connection is None:
        return
    stream = _POST_ACTION_ASSESSMENTS.get((connection.kind, request.action))
    if stream is None:
        return
    from icuhub.core.queue import DuplicateActiveJob  # noqa: PLC0415
    from icuhub.core.sync import trigger_sync  # noqa: PLC0415

    try:
        await trigger_sync(
            session,
            Caller(id="action-completion", tenant_id=request.tenant_id, roles=frozenset({"system"})),
            connection.id,
            stream,
            mode="full",
        )
    except DuplicateActiveJob:
        # The active authoritative read covers the same checkpoint; never enqueue a duplicate.
        pass


class _ReadOnlyHttp:
    """VendorHttp facade that rejects vendor writes during planning (GAP-PLAT plan safety)."""

    def __init__(self, inner: Any, allowed_post_paths: tuple[str, ...] = ()) -> None:
        self._inner = inner
        self._allowed = frozenset(allowed_post_paths)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def _guard(self, method: str, url: str) -> None:
        verb = method.upper()
        if verb in ("GET", "HEAD", "OPTIONS"):
            return
        path = urlsplit(str(url)).path
        if verb == "POST" and any(
            path == allowed or (allowed.endswith("/") and path.startswith(allowed)) for allowed in self._allowed
        ):
            return
        raise AssertionError(f"plan must not send vendor writes: {verb} {url}")

    async def request(self, method: str, path_or_url: str, **kwargs: Any) -> Any:
        self._guard(method, path_or_url)
        return await self._inner.request(method, path_or_url, **kwargs)

    async def stream_download(self, method: str, url: str, *, max_bytes: int, headers: Any = None) -> Any:
        self._guard(method, url)
        return await self._inner.stream_download(method, url, max_bytes=max_bytes, headers=headers)

    async def stream_download_result(
        self,
        method: str,
        url: str,
        *,
        max_bytes: int,
        params: Any = None,
        headers: Any = None,
        expected: Any = (200,),
    ) -> Any:
        self._guard(method, url)
        return await self._inner.stream_download_result(
            method, url, max_bytes=max_bytes, params=params, headers=headers, expected=expected
        )


async def _transition(
    session: AsyncSession,
    request: ActionRequest,
    state: str,
    *,
    caller_id: str,
    detail: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    error_class: str | None = None,
) -> None:
    request.state = state
    request.updated_at = datetime.now(UTC)
    if result is not None:
        request.result_json = result
    if error_class is not None:
        request.error_class = error_class
    await audit_append(
        session,
        request.tenant_id,
        ts=datetime.now(UTC),
        caller_id=caller_id,
        connection_id=request.connection_id,
        operation=f"action.{request.action}",
        classification=request.classification,
        decision=request.decision,
        args_digest=request.args_digest,
        status=state,
        detail_json=detail or {"state": state},
        correlation_id=request.correlation_id,
    )
    from icuhub.core.outbox import add_event  # noqa: PLC0415 - keeps transition module light for workers

    await add_event(
        session,
        request.tenant_id,
        CloudEvent(
            id=f"action-{request.id}-{state}-{uuid.uuid4()}",
            source=f"icuhub://actions/{request.id}",
            type=f"icuhub.action.{state}",
            subject=str(request.id),
            time=datetime.now(UTC),
            data={"action": request.action, "connection_id": str(request.connection_id), "state": state},
        ),
    )
    if state in ("succeeded", "failed", "no_op", "stale_plan", "unverified"):
        from icuhub.core.evidence_export import _action, _outcome_digest  # noqa: PLC0415

        digest = _outcome_digest(_action(request))
        if digest is None:  # pragma: no cover - _action always emits an outcome object
            raise RuntimeError("terminal action outcome has no evidence digest")
        await _record_case_evidence(
            session,
            request,
            kind="outcome",
            ref_table="action_request",
            ref_id=request.id,
            digest=digest,
        )
    if state == "succeeded":
        await _schedule_post_action_assessment(session, request)
    if state in ("succeeded", "failed", "no_op", "stale_plan", "outcome_unknown", "unverified"):
        from icuhub.core.tickets import on_action_terminal  # noqa: PLC0415 - tickets builds actions

        await on_action_terminal(session, request)


async def _plan(
    connector: Connector, spec: ActionSpec, args: dict[str, Any]
) -> ActionPlan:
    parsed = spec.input_model.model_validate(args)
    read_only = _ReadOnlyHttp(connector.ctx.http, allowed_post_paths=connector.plan_safe_post_paths)
    original = connector.ctx.http
    connector.ctx.http = read_only
    try:
        return await getattr(connector, spec.plan.__name__)(parsed)
    finally:
        connector.ctx.http = original


def _store_plan(request: ActionRequest, plan: ActionPlan) -> ActionPlanRow:
    return ActionPlanRow(
        action_request_id=request.id,
        tenant_id=request.tenant_id,
        target_ref=plan.target_ref,
        diff_json=plan.diff,
        preconditions_json=plan.preconditions,
        request_json=plan.request,
        idempotency_key=plan.idempotency_key,
        plan_hash=plan.plan_hash,
        changed=plan.changed,
    )


async def _replay_existing(
    session: AsyncSession,
    caller: Caller,
    *,
    action: str,
    args_digest: str,
    idempotency_key: str,
    connection_id: uuid.UUID,
    natural_key: str | None,
) -> ActionRequest | None:
    """Return the request an equivalent submission already admitted, or None.

    A matching idempotency key replays for the same caller. An active natural key on the same
    connection and action replays for any caller. Different arguments under either identity are
    refused with ``Conflict``.
    """
    by_key = (
        await session.execute(
            select(ActionRequest).where(
                ActionRequest.tenant_id == caller.tenant_id,
                ActionRequest.caller_id == caller.id,
                ActionRequest.idempotency_key == idempotency_key,
            )
        )
    ).scalar_one_or_none()
    if by_key is not None:
        if by_key.args_digest != args_digest or by_key.action != action:
            raise Conflict("idempotency key was already used with different arguments")
        return by_key
    if natural_key is None:
        return None
    by_natural = (
        await session.execute(
            select(ActionRequest).where(
                ActionRequest.tenant_id == caller.tenant_id,
                ActionRequest.connection_id == connection_id,
                ActionRequest.action == action,
                ActionRequest.natural_key == natural_key,
                ActionRequest.state.in_(ACTION_ACTIVE_STATES),
            )
        )
    ).scalar_one_or_none()
    if by_natural is None:
        return None
    if by_natural.args_digest != args_digest:
        raise Conflict("natural key already has an active request with different arguments")
    return by_natural


async def _admit(
    session: AsyncSession,
    caller: Caller,
    *,
    connection_id: uuid.UUID,
    action: str,
    classification: str,
    args: dict[str, Any],
    args_digest: str,
    idempotency_key: str,
    correlation_id: str | None,
    mode: str,
    natural_key: str | None,
) -> tuple[ActionRequest, bool]:
    """Insert a ``received`` request, or return the equivalent one a concurrent submission admitted.

    The insert runs in a savepoint. The partial unique index on the natural key (and the
    idempotency unique constraint) turn a concurrent duplicate into ``IntegrityError``; the winner
    is then re-read and replayed or refused. Returns ``(request, created)``.
    """
    replay = await _replay_existing(
        session,
        caller,
        action=action,
        args_digest=args_digest,
        idempotency_key=idempotency_key,
        connection_id=connection_id,
        natural_key=natural_key,
    )
    if replay is not None:
        return replay, False
    request = ActionRequest(
        tenant_id=caller.tenant_id,
        connection_id=connection_id,
        action=action,
        classification=classification,
        args_json=args,
        args_digest=args_digest,
        caller_id=caller.id,
        correlation_id=correlation_id,
        idempotency_key=idempotency_key,
        natural_key=natural_key,
        mode=mode,
        state="received",
    )
    try:
        async with session.begin_nested():
            session.add(request)
            await session.flush()
    except IntegrityError as exc:
        replay = await _replay_existing(
            session,
            caller,
            action=action,
            args_digest=args_digest,
            idempotency_key=idempotency_key,
            connection_id=connection_id,
            natural_key=natural_key,
        )
        if replay is None:
            raise Conflict("action request was claimed by a concurrent submission; retry") from exc
        return replay, False
    return request, True


async def submit_action(
    session: AsyncSession,
    caller: Caller,
    connection_id: uuid.UUID,
    action: str,
    args: dict[str, Any],
    *,
    idempotency_key: str,
    correlation_id: str | None = None,
    mode: str = "live",
) -> ActionRequest:
    """Create (or replay) an action request through plan and policy."""
    services = get_services()
    args_digest = _digest(args)
    existing = await _replay_existing(
        session,
        caller,
        action=action,
        args_digest=args_digest,
        idempotency_key=idempotency_key,
        connection_id=connection_id,
        natural_key=None,
    )
    if existing is not None:
        return existing
    connection = await session.get(Connection, connection_id)
    if connection is None or connection.tenant_id != caller.tenant_id:
        raise NotFound("connection not found")
    cls = services.runtime._class(connection)
    spec = cls.actions().get(action)
    if spec is None:
        raise NotFound(f"{connection.kind} has no action {action!r}")
    if connection.allowed_operations is not None and action not in connection.allowed_operations:
        raise PermissionDenied(f"action {action!r} is not enabled on this connection")
    connector = await services.runtime.open(session, caller.tenant_id, connection.id)
    plan = await _plan(connector, spec, args)
    natural_key = plan.idempotency_key if spec.idempotency == "natural_key" else None
    request, created = await _admit(
        session,
        caller,
        connection_id=connection.id,
        action=action,
        classification=spec.classification,
        args=args,
        args_digest=args_digest,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
        mode=mode,
        natural_key=natural_key,
    )
    if not created:
        return request
    session.add(_store_plan(request, plan))
    await _record_case_evidence(
        session,
        request,
        kind="action_plan",
        ref_table="action_plan",
        ref_id=request.id,
        digest=plan.plan_hash,
    )
    rules = list(
        (await session.execute(select(PolicyRule).where(PolicyRule.tenant_id == caller.tenant_id))).scalars().all()
    )
    decision = evaluate(
        rules,
        PolicyInput(
            caller=caller,
            connection_id=connection.id,
            connection_kind=connection.kind,
            operation=action,
            classification=spec.classification,  # type: ignore[arg-type]
            egress_class=connection.egress_class,
            args=args,
            mode=mode,  # type: ignore[arg-type]
        ),
    )
    request.decision = decision.decision
    request.rule_id = decision.rule_id
    tenant = await session.get(Tenant, caller.tenant_id)
    outcome = effective_outcome(
        decision,
        PolicyInput(
            caller=caller,
            connection_id=connection.id,
            connection_kind=connection.kind,
            operation=action,
            classification=spec.classification,  # type: ignore[arg-type]
            egress_class=connection.egress_class,
            args=args,
            mode=mode,  # type: ignore[arg-type]
        ),
        deployment_switch=services.settings.automation_enabled,
        tenant_switch=bool(tenant and tenant.automation_enabled),
    )
    if outcome == "denied":
        await _transition(session, request, "denied", caller_id=caller.id, detail={"reason": decision.reason})
        return request
    if not plan.changed:
        await _transition(session, request, "no_op", caller_id=caller.id, result={"status": "no_op"})
        return request
    if outcome == "preview":
        await _transition(session, request, "previewed", caller_id=caller.id, result={"plan": plan.model_dump(mode="json")})
        return request
    if outcome == "pending_approval":
        approval = Approval(
            tenant_id=caller.tenant_id,
            action_request_id=request.id,
            approver_group=decision.approver_group,
            plan_hash=plan.plan_hash,
            expires_at=datetime.now(UTC) + timedelta(seconds=decision.ttl_s),
        )
        session.add(approval)
        await session.flush()
        await _transition(session, request, "pending_approval", caller_id=caller.id)

        from icuhub.core.notifier import notify_approval  # noqa: PLC0415


        await notify_approval(session, approval)
        return request
    await _transition(session, request, "approved", caller_id=caller.id)
    await enqueue(
        session,
        "actions",
        "apply",
        {"action_request_id": str(request.id), "tenant_id": str(request.tenant_id)},
        tenant_id=caller.tenant_id,
        dedupe_key=f"{caller.tenant_id}:apply:{request.id}",
    )
    return request


async def decide(
    session: AsyncSession,
    caller: Caller,
    approval_id: uuid.UUID,
    decision: Literal["approved", "rejected"],
    reason: str | None = None,
    change_ref: str | None = None,
) -> ActionRequest:
    """Approve or reject a pending approval with SoD and expiry checks."""
    approval = await session.get(Approval, approval_id)
    if approval is None or approval.tenant_id != caller.tenant_id:
        raise NotFound("approval not found")
    request = await session.get(ActionRequest, approval.action_request_id)
    if request is None:
        raise NotFound("action request not found")
    if approval.decision is not None or request.state != "pending_approval":
        raise Conflict(f"approval is already {approval.decision or request.state}")
    if approval.expires_at <= datetime.now(UTC):
        approval.decision = "expired"
        approval.decided_at = datetime.now(UTC)
        await _transition(session, request, "expired", caller_id=caller.id)
        await _record_approval_evidence(session, request, approval)
        return request
    # Direct membership, not has_role: has_role treats admin as every role, and FR-ADM-03 forbids admin approval.
    if "approver" not in caller.roles:
        raise PermissionDenied("approval requires the approver role")
    if caller.id == request.caller_id:
        raise PermissionDenied("requester cannot approve their own action (SoD)")
    if approval.approver_group and approval.approver_group not in caller.groups:
        raise PermissionDenied(f"approver must be in group {approval.approver_group!r}")
    approval.decision = decision
    approval.decided_by = caller.id
    approval.decided_at = datetime.now(UTC)
    approval.reason = reason
    approval.change_ref = change_ref
    await _transition(session, request, "approved" if decision == "approved" else "rejected", caller_id=caller.id)
    await _record_approval_evidence(session, request, approval)
    if decision == "approved":
        await enqueue(
            session,
            "actions",
            "apply",
            {"action_request_id": str(request.id), "tenant_id": str(request.tenant_id)},
            tenant_id=caller.tenant_id,
            dedupe_key=f"{caller.tenant_id}:apply:{request.id}",
        )
    return request


async def expire_approvals(session: AsyncSession, tenant_id: uuid.UUID) -> int:
    """Mark due approvals expired; returns the number expired."""
    now = datetime.now(UTC)
    approvals = list(
        (
            await session.execute(
                select(Approval).where(
                    Approval.tenant_id == tenant_id, Approval.decision.is_(None), Approval.expires_at <= now
                )
            )
        )
        .scalars()
        .all()
    )
    for approval in approvals:
        request = await session.get(ActionRequest, approval.action_request_id)
        if request is None or request.state != "pending_approval":
            continue
        approval.decision = "expired"
        approval.decided_at = now
        await _transition(session, request, "expired", caller_id="system")
    return len(approvals)


async def run_expire_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    async with session_scope(uuid.UUID(payload["tenant_id"])) as session:
        count = await expire_approvals(session, uuid.UUID(payload["tenant_id"]))
    return {"expired": count}


def _reconcile_counters(request: ActionRequest) -> tuple[int, int]:
    """Return ``(polls, reconcile_attempts)`` persisted beside the outcome in ``result_json``."""
    stored = request.result_json or {}
    return int(stored.get("polls", 0)), int(stored.get("reconcile_attempts", 0))


def _prior_outcome(request: ActionRequest) -> ActionOutcome:
    """Rebuild the outcome persisted by the last transition; reconcile receives this, never a re-derivation."""
    stored = request.result_json or {}
    status = "accepted_async" if request.state == "accepted_async" else "outcome_unknown"
    return ActionOutcome(
        status=status,
        vendor_ref=stored.get("vendor_ref"),
        result=stored.get("result") or {},
        error=stored.get("error"),
    )


def _persisted(outcome: ActionOutcome, *, polls: int, attempts: int) -> dict[str, Any]:
    """Outcome plus job counters; ``_transition`` overwrites ``result_json`` wholesale, so counters travel with it."""
    return {**outcome.model_dump(mode="json"), "polls": polls, "reconcile_attempts": attempts}


async def _enqueue_reconcile(
    session: AsyncSession,
    request: ActionRequest,
    *,
    run_at: datetime | None = None,
    dedupe_key: str | None = None,
) -> None:
    await enqueue(
        session,
        "actions",
        "reconcile",
        {"action_request_id": str(request.id), "tenant_id": str(request.tenant_id)},
        tenant_id=request.tenant_id,
        run_at=run_at,
        dedupe_key=dedupe_key,
    )


async def _renew_lease(lease: Lease) -> None:
    """Extend the job lease every ``ttl / 3`` until cancelled, lost, or unable to reach the queue.

    Renewal only keeps a slow vendor send from being reclaimed mid-flight. A reclaimed job that
    finds ``executing`` never resends: it records ``outcome_unknown`` and reconciles.
    """
    interval = lease.ttl.total_seconds() / 3
    current = lease
    while True:
        await asyncio.sleep(interval)
        try:
            current = await heartbeat(current)
        except LeaseLost:
            _LOG.warning("apply lease lost for job %s; send continues without renewal", lease.job_id)
            return
        except (OSError, TimeoutError, RuntimeError):
            _LOG.exception("apply lease renewal failed for job %s; send continues without renewal", lease.job_id)
            return


async def run_apply_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    """Run one apply attempt with lease renewal across planning and the vendor send."""
    if lease is None:
        return await _run_apply_job(payload)
    renewer = asyncio.create_task(_renew_lease(lease))
    try:
        return await _run_apply_job(payload)
    finally:
        renewer.cancel()
        await asyncio.gather(renewer, return_exceptions=True)


async def _run_apply_job(payload: dict[str, Any]) -> dict[str, Any]:
    """Run the durable apply state machine without owning lease renewal."""
    services = get_services()
    request_id = uuid.UUID(payload["action_request_id"])
    tenant_id = uuid.UUID(payload["tenant_id"])
    # Block A: plan, verify the stored plan hash, and commit the `executing` claim before any vendor write.
    async with session_scope(tenant_id) as session:
        request = await session.get(ActionRequest, request_id)
        if request is None:
            return {"skipped": True}
        if request.state == "executing":
            # A prior attempt committed the claim but recorded no outcome; the vendor send may already have happened.
            await _transition(session, request, "outcome_unknown", caller_id="worker", error_class="ExecutionInterrupted")
            await _enqueue_reconcile(session, request, dedupe_key=f"{tenant_id}:reconcile:{request.id}")
            return {"state": "outcome_unknown"}
        if request.state != "approved":
            return {"skipped": True, "state": request.state}
        stored_plan = await session.get(ActionPlanRow, request.id)
        if stored_plan is None:
            await _transition(session, request, "failed", caller_id="worker", error_class="MissingStoredPlan")
            return {"state": "failed", "error": "MissingStoredPlan"}
        connection = await session.get(Connection, request.connection_id)
        cls = services.runtime._class(connection)
        spec = cls.actions()[request.action]
        connector = await services.runtime.open(session, request.tenant_id, request.connection_id)
        try:
            fresh = await _plan(connector, spec, request.args_json)
        except StalePlan:
            await _transition(session, request, "stale_plan", caller_id="worker", error_class="StalePlan")
            return {"state": "stale_plan"}
        except Exception as exc:  # noqa: BLE001 - failure class is recorded at this boundary
            await _transition(session, request, "failed", caller_id="worker", error_class=type(exc).__name__)
            return {"state": "failed", "error": type(exc).__name__}
        if fresh.plan_hash != stored_plan.plan_hash:
            await _transition(session, request, "stale_plan", caller_id="worker", error_class="StalePlan")
            return {"state": "stale_plan"}
        await _transition(session, request, "executing", caller_id="worker")
    # Block B: the claim is durable; reopen the connector on this session so secrets resolve against it.
    async with session_scope(tenant_id) as session:
        request = await session.get(ActionRequest, request_id)
        if request is None or request.state != "executing":
            return {"skipped": True}
        connector = await services.runtime.open(session, request.tenant_id, request.connection_id)
        try:
            outcome: ActionOutcome = await getattr(connector, spec.apply.__name__)(fresh)
        except StalePlan:
            await _transition(session, request, "stale_plan", caller_id="worker", error_class="StalePlan")
            return {"state": "stale_plan"}
        except Exception as exc:  # noqa: BLE001 - failure class is recorded at this boundary
            await _transition(session, request, "failed", caller_id="worker", error_class=type(exc).__name__)
            return {"state": "failed", "error": type(exc).__name__}
        result = outcome.model_dump(mode="json")
        if outcome.status == "accepted_async":
            # The apply is never repeated: reconcile polls the vendor using the persisted vendor_ref.
            await _transition(
                session,
                request,
                "accepted_async",
                caller_id="worker",
                result=_persisted(outcome, polls=1, attempts=0),
            )
            await _enqueue_reconcile(
                session,
                request,
                run_at=datetime.now(UTC) + timedelta(seconds=30),
                dedupe_key=f"{request.tenant_id}:reconcile:{request.id}",
            )
            return {"state": "accepted_async"}
        if outcome.status == "outcome_unknown":
            await _transition(session, request, "outcome_unknown", caller_id="worker", result=result)
            await _enqueue_reconcile(session, request, dedupe_key=f"{request.tenant_id}:reconcile:{request.id}")
            return {"state": "outcome_unknown"}
        await _transition(session, request, outcome.status, caller_id="worker", result=result)
        return {"state": outcome.status}


async def _exhaust_reconcile(session: AsyncSession, request: ActionRequest, error_class: str, attempts: int) -> None:
    """Read-back keeps failing: record ``outcome_unknown`` and enqueue nothing further.

    The write may or may not have happened and no read-back established either way, so the
    request stays in the reconcilable ``outcome_unknown`` state for operator follow-up.
    """
    await _transition(
        session,
        request,
        "outcome_unknown",
        caller_id="worker",
        result={**(request.result_json or {}), "reconcile_attempts": attempts},
        error_class=error_class,
    )


async def run_reconcile_job(payload: dict[str, Any], lease: Any = None) -> dict[str, Any]:
    """Worker handler resolving ``accepted_async`` and ``outcome_unknown`` through the reconcile hook.

    Reconcile receives the stored approved plan and the persisted prior outcome. It never
    re-plans, never re-applies, and never mutates the stored plan or its hash.
    """
    services = get_services()
    request_id = uuid.UUID(payload["action_request_id"])
    async with session_scope(uuid.UUID(payload["tenant_id"])) as session:
        request = await session.get(ActionRequest, request_id)
        if request is None or request.state not in ("accepted_async", "outcome_unknown"):
            return {"skipped": True}
        connection = await session.get(Connection, request.connection_id)
        cls = services.runtime._class(connection)
        spec = cls.actions()[request.action]
        if spec.reconcile is None:
            await _transition(session, request, "unverified", caller_id="worker", error_class="NoReconciliationPath")
            return {"state": "unverified"}
        connector = await services.runtime.open(session, request.tenant_id, request.connection_id)
        stored = await session.get(ActionPlanRow, request.id)
        plan = ActionPlan(
            action=request.action,
            target_ref=stored.target_ref,
            diff=stored.diff_json,
            preconditions=stored.preconditions_json,
            idempotency_key=stored.idempotency_key,
            changed=stored.changed,
            request=stored.request_json,
        )
        polls, attempts = _reconcile_counters(request)
        # Re-enqueues below carry no dedupe key: this job is itself the active holder of the reconcile key.
        try:
            outcome: ActionOutcome = await getattr(connector, spec.reconcile.__name__)(plan, _prior_outcome(request))
        except Exception as exc:  # noqa: BLE001 - failure class is recorded at this boundary
            attempts += 1
            if attempts >= _MAX_RECONCILE_ATTEMPTS:
                await _exhaust_reconcile(session, request, type(exc).__name__, attempts)
                return {"state": "outcome_unknown", "attempts": attempts}
            request.result_json = {**(request.result_json or {}), "reconcile_attempts": attempts}
            await _enqueue_reconcile(session, request, run_at=datetime.now(UTC) + timedelta(seconds=min(300, 15 * attempts)))
            return {"state": request.state, "attempts": attempts}
        if outcome.status == "accepted_async":
            polls += 1
            if polls > _MAX_ASYNC_POLLS:
                await _transition(session, request, "unverified", caller_id="worker", error_class="AsyncTimeout")
                return {"state": "unverified"}
            await _transition(
                session,
                request,
                "accepted_async",
                caller_id="worker",
                result=_persisted(outcome, polls=polls, attempts=attempts),
            )
            await _enqueue_reconcile(session, request, run_at=datetime.now(UTC) + timedelta(seconds=30))
            return {"state": "accepted_async", "polls": polls}
        if outcome.status == "outcome_unknown":
            attempts += 1
            if attempts >= _MAX_RECONCILE_ATTEMPTS:
                await _exhaust_reconcile(session, request, "ReconcileExhausted", attempts)
                return {"state": "outcome_unknown", "attempts": attempts}
            persisted = _persisted(outcome, polls=polls, attempts=attempts)
            if request.state == "outcome_unknown":
                request.result_json = persisted
            else:
                await _transition(session, request, "outcome_unknown", caller_id="worker", result=persisted)
            await _enqueue_reconcile(session, request, run_at=datetime.now(UTC) + timedelta(seconds=min(300, 15 * attempts)))
            return {"state": "outcome_unknown", "attempts": attempts}
        await _transition(session, request, outcome.status, caller_id="worker", result=outcome.model_dump(mode="json"))
        return {"state": outcome.status}


JOB_HANDLERS = {
    "apply": run_apply_job,
    "reconcile": run_reconcile_job,
    "expire_approvals": run_expire_job,
}
