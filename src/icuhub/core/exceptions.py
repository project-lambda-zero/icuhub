"""Exception authority and governed source suppression (F3: FR-GRC-04, FR-COR-05).

Archer is the sole authority for exception decisions. A decision block on an Archer
``exception_requests`` record sets ``CorrelationCase.exception_state``. Approval alone never
touches a source. Suppression at the source is a separate ``submit_action`` request, so it runs
its own plan, policy, and approval, and it is bound to the approved revision and expiry.

Convergence is level-triggered. ``converge_case`` compares the suppression owed by the case
(approved, unexpired, in scope) with every F3 suppression request recorded for the case, and
submits only the missing suppressions and the reversals that are no longer owed. The entry points
are the decision handler, the scheduled expiry job, and the terminal hook for any F3 action
request. A suppression that succeeds after its exception was rejected or expired is therefore
reversed when it lands.

Expiry is scheduled on the queue at ``exception_expires_at``. Expiry and rejection enqueue a full
source sync for each affected (connection, stream, target) once no reversal is outstanding.

Suppression policy is hub-owned. The target connection's ``config_json["suppression"]`` names the
suppress and reverse actions and their argument templates. Vendor payloads never name an action.

Decision contract. An ``exception_requests`` SourceRecord carries its decision in ``data["exception"]``:
``{"status": "requested" | "approved" | "rejected", "correlation_key": str, "revision": str,
"scope": {"source_uids": [str, ...]}, "expires_at": ISO-8601 timezone-aware str}``. ``scope`` and
``expires_at`` are required only when ``status`` is ``approved``. Any other shape is ignored.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.actions import submit_action
from icuhub.core.auth_types import Caller
from icuhub.core.queue import DuplicateActiveJob, enqueue
from icuhub.core.sync import trigger_sync
from icuhub.core.tickets import case_event, render_arg
from icuhub.kit.types import SourceRecord
from icuhub.storage.db import session_scope
from icuhub.storage.models import ActionRequest, CaseMember, Connection, CorrelationCase, Finding

__all__ = [
    "CALLER_ID",
    "JOB_HANDLERS",
    "SuppressionPolicyError",
    "converge_after_terminal",
    "converge_case",
    "on_exception_decision",
    "run_exception_expiry_job",
]

_log = logging.getLogger(__name__)

CALLER_ID: Final = "exception-decision"
EXPIRY_KIND: Final = "exception_expiry"
_ARCHER_DECISIONS: Final = frozenset({"requested", "approved", "rejected"})
_MAX_SCOPE_UIDS: Final = 500
_SUPPRESS_PREFIX: Final = "f3:suppress:"
_REVERSE_PREFIX: Final = "f3:reverse:"
_CONVERGING: Final = "f3_converging"
# Action states, as set by actions.py. A request in _NON_TERMINAL may still change. _REVERSED is a
# settled reversal: either the vendor state was changed (succeeded) or it already held (no_op).
_NON_TERMINAL: Final = frozenset({"pending_approval", "approved", "executing", "accepted_async", "outcome_unknown"})
_REVERSED: Final = frozenset({"succeeded", "no_op"})
# Suppression end states that are not resubmitted automatically for the same digest. A human denial
# or rejection is not overridden, failures are not retried in a loop, and an expired approval waits
# for a new Archer decision (a new revision or expiry produces a new digest).
_DEAD_FOR_WANTED: Final = frozenset({"denied", "rejected", "expired", "failed", "stale_plan", "previewed"})


class SuppressionPolicyError(RuntimeError):
    """A connection's suppression policy is malformed, or required reversal config is missing."""


@dataclass(frozen=True)
class _Decision:
    status: str  # effective status: requested | approved | rejected (unparseable expiry downgrades approved)
    correlation_key: str
    revision: str
    scope_uids: frozenset[str]
    expires_at: datetime | None


@dataclass(frozen=True)
class _SuppressionPolicy:
    action: str
    args: dict[str, Any]
    reversal_action: str
    reversal_args: dict[str, Any]


@dataclass(frozen=True)
class _Wanted:
    """The suppression the case owes right now: one approved revision with one expiry."""

    digest: str
    revision: str
    expires_at: datetime
    scope_uids: frozenset[str]


def _parse_expiry(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _parse_decision(record: SourceRecord) -> _Decision | None:
    """Return the decision carried by an Archer record, or None when the block is absent or invalid."""
    block = record.data.get("exception")
    if not isinstance(block, dict):
        return None
    status = block.get("status")
    correlation_key = block.get("correlation_key")
    revision = block.get("revision")
    if status not in _ARCHER_DECISIONS:
        return None
    if not isinstance(correlation_key, str) or not correlation_key:
        return None
    if not isinstance(revision, str) or not revision:
        return None
    if status != "approved":
        return _Decision(status, correlation_key, revision, frozenset(), None)
    scope = block.get("scope")
    uids = scope.get("source_uids") if isinstance(scope, dict) else None
    if not isinstance(uids, list) or not uids or not all(isinstance(uid, str) and uid for uid in uids):
        return None
    if len(uids) > _MAX_SCOPE_UIDS:
        _log.warning("exception decision scope exceeds %d entries; decision rejected (uid=%s)", _MAX_SCOPE_UIDS, record.uid)
        return None
    expires_at = _parse_expiry(block.get("expires_at"))
    if expires_at is None:
        # An approval without a parseable expiry is not an approval: it grants no suppression.
        return _Decision("requested", correlation_key, revision, frozenset(), None)
    return _Decision("approved", correlation_key, revision, frozenset(uids), expires_at)


def _policy(connection: Connection | None) -> _SuppressionPolicy | None:
    raw = (connection.config_json or {}).get("suppression") if connection is not None else None
    if raw is None:
        return None
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("action"), str)
        or not isinstance(raw.get("reversal_action"), str)
        or not isinstance(raw.get("args"), dict)
        or not isinstance(raw.get("reversal_args"), dict)
    ):
        raise SuppressionPolicyError("connection suppression policy is malformed")
    return _SuppressionPolicy(raw["action"], raw["args"], raw["reversal_action"], raw["reversal_args"])


def _caller(case: CorrelationCase) -> Caller:
    return Caller(id=CALLER_ID, tenant_id=case.tenant_id, roles=frozenset({"system"}))


def _digest(revision: str, expires_at: datetime) -> str:
    return hashlib.sha256(f"{revision}|{expires_at.astimezone(UTC).isoformat()}".encode()).hexdigest()[:32]


def _suppression_key(case_id: uuid.UUID, finding_id: uuid.UUID, digest: str, epoch: int) -> str:
    return f"{_SUPPRESS_PREFIX}{case_id}:{finding_id}:{digest}:{epoch}"


def _parse_suppression_key(key: str) -> tuple[uuid.UUID, str]:
    """Return (finding_id, digest) from a key written by ``_suppression_key``."""
    parts = key.split(":")
    return uuid.UUID(parts[3]), parts[4]


def _wanted(case: CorrelationCase, now: datetime) -> _Wanted | None:
    if case.exception_state != "approved" or not case.exception_revision or case.exception_expires_at is None:
        return None
    if case.exception_expires_at <= now:
        return None
    return _Wanted(
        _digest(case.exception_revision, case.exception_expires_at),
        case.exception_revision,
        case.exception_expires_at,
        frozenset(case.exception_scope_uids or ()),
    )


async def _members(session: AsyncSession, case: CorrelationCase) -> list[Finding]:
    return list(
        (
            await session.execute(
                select(Finding)
                .join(CaseMember, CaseMember.finding_id == Finding.id)
                .where(CaseMember.case_id == case.id)
                .order_by(Finding.id)
            )
        )
        .scalars()
        .all()
    )


async def _suppression_requests(session: AsyncSession, case: CorrelationCase) -> list[ActionRequest]:
    """Every F3 suppression request recorded for the case, including findings no longer members."""
    return list(
        (
            await session.execute(
                select(ActionRequest)
                .where(
                    ActionRequest.tenant_id == case.tenant_id,
                    ActionRequest.caller_id == CALLER_ID,
                    ActionRequest.correlation_id == str(case.id),
                    ActionRequest.idempotency_key.startswith(f"{_SUPPRESS_PREFIX}{case.id}:"),
                )
                .order_by(ActionRequest.created_at)
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


async def _find_reversal(session: AsyncSession, case: CorrelationCase, request: ActionRequest) -> ActionRequest | None:
    return (
        await session.execute(
            select(ActionRequest)
            .where(
                ActionRequest.tenant_id == case.tenant_id,
                ActionRequest.caller_id == CALLER_ID,
                ActionRequest.idempotency_key == f"{_REVERSE_PREFIX}{request.id}",
            )
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _submit_reversal(
    session: AsyncSession, case: CorrelationCase, request: ActionRequest, finding: Finding
) -> ActionRequest:
    policy = _policy(await session.get(Connection, request.connection_id))
    if policy is None:
        raise SuppressionPolicyError(f"cannot reverse suppression {request.id}: connection has no suppression policy")
    values = {"source_uid": finding.source_uid or "", "exception_revision": case.exception_revision or ""}
    return await submit_action(
        session,
        _caller(case),
        request.connection_id,
        policy.reversal_action,
        {key: render_arg(value, values) for key, value in policy.reversal_args.items()},
        idempotency_key=f"{_REVERSE_PREFIX}{request.id}",
        correlation_id=str(case.id),
    )


async def _converge_finding(
    session: AsyncSession,
    case: CorrelationCase,
    finding: Finding,
    requests: list[ActionRequest],
    wanted: _Wanted | None,
) -> tuple[bool, bool]:
    """Reverse what is no longer owed for one finding, then submit the owed suppression.

    Returns ``(blocking, settled)``. ``blocking`` means an action is still in flight, so nothing
    new is submitted for the finding. ``settled`` means a reversal reached a reversed state in
    this pass.
    """
    blocking = False
    settled = False
    live: set[str] = set()
    dead: set[str] = set()
    for request in requests:
        _, digest = _parse_suppression_key(request.idempotency_key)
        if request.state in _NON_TERMINAL:
            blocking = True
            continue
        if request.state == "no_op":
            # The desired state already held at the vendor. We did not change it, so it is never reversed.
            if wanted is not None and digest == wanted.digest and finding.source_uid in wanted.scope_uids:
                live.add(digest)
            continue
        if request.state != "succeeded":
            if wanted is not None and digest == wanted.digest and request.state in _DEAD_FOR_WANTED:
                dead.add(digest)
            continue
        reversal = await _find_reversal(session, case, request)
        if reversal is not None and reversal.state in _NON_TERMINAL:
            blocking = True
            continue
        if reversal is not None and reversal.state in _REVERSED:
            continue
        if wanted is not None and digest == wanted.digest and finding.source_uid in wanted.scope_uids:
            live.add(digest)
            continue
        if reversal is None:
            reversal = await _submit_reversal(session, case, request, finding)
            if reversal.state in _NON_TERMINAL:
                blocking = True
            elif reversal.state in _REVERSED:
                settled = True
        if reversal.state not in _NON_TERMINAL and reversal.state not in _REVERSED:
            # Not retried here: the reversal key is idempotent, and the vendor-side dismiss_until bounds
            # the exposure. The operator sees the failed reversal in the action request record.
            _log.error(
                "suppression reversal %s ended in %s; suppression %s remains live",
                reversal.id,
                reversal.state,
                request.id,
            )
    if blocking or wanted is None or finding.source_uid not in wanted.scope_uids:
        return blocking, settled
    if wanted.digest in live or wanted.digest in dead:
        return blocking, settled
    policy = _policy(await session.get(Connection, finding.connection_id))
    if policy is None:
        _log.warning("connection has no suppression policy; approved finding not suppressed (finding=%s)", finding.id)
        return blocking, settled
    epoch = sum(1 for request in requests if _parse_suppression_key(request.idempotency_key)[1] == wanted.digest)
    values = {
        "source_uid": finding.source_uid or "",
        "exception_revision": wanted.revision,
        "exception_expires_at": wanted.expires_at.astimezone(UTC).isoformat(),
    }
    submitted = await submit_action(
        session,
        _caller(case),
        finding.connection_id,
        policy.action,
        {key: render_arg(value, values) for key, value in policy.args.items()},
        idempotency_key=_suppression_key(case.id, finding.id, wanted.digest, epoch),
        correlation_id=str(case.id),
    )
    return blocking or submitted.state in _NON_TERMINAL, settled


async def _enqueue_reconcile(session: AsyncSession, case: CorrelationCase, findings: list[Finding]) -> None:
    """Request an authoritative full sync for each (connection, stream, target) the case touches."""
    seen: set[tuple[uuid.UUID, str, uuid.UUID | None]] = set()
    for finding in findings:
        key = (finding.connection_id, finding.stream, finding.target_id)
        if key in seen:
            continue
        seen.add(key)
        try:
            await trigger_sync(
                session,
                _caller(case),
                finding.connection_id,
                finding.stream,
                target_id=finding.target_id,
                mode="full",
            )
        except DuplicateActiveJob:
            continue


async def _schedule_expiry(session: AsyncSession, case: CorrelationCase, *, rearm: bool = False) -> None:
    expires_at = case.exception_expires_at
    if expires_at is None:
        return
    key = f"{case.tenant_id}:{EXPIRY_KIND}:{case.id}:{expires_at.isoformat()}"
    if rearm:
        # The running job holds ``key``. A rearmed job needs its own key to be queued behind it.
        key = f"{key}:rearm:{uuid.uuid4().hex}"
    try:
        await enqueue(
            session,
            "actions",
            EXPIRY_KIND,
            {"tenant_id": str(case.tenant_id), "case_id": str(case.id), "scheduled_for": expires_at.isoformat()},
            tenant_id=case.tenant_id,
            run_at=expires_at,
            dedupe_key=key,
        )
    except DuplicateActiveJob:
        return


async def converge_case(
    session: AsyncSession, case_id: uuid.UUID, *, ended: bool = False, reversal_settled: bool = False
) -> None:
    """Make the case's suppression match what it owes. The only mutation path for suppression.

    ``ended`` is set when the exception was rejected or expired. ``reversal_settled`` is set when a
    reversal reached a reversed state. Both gate the full source reconciliation: it is enqueued only
    once no action is in flight and nothing is owed.

    Re-entry (a terminal hook fired by a request this pass submitted) returns immediately. The
    outer pass already sees that request's terminal state and decides the next step.
    """
    if session.info.get(_CONVERGING):
        return
    session.info[_CONVERGING] = True
    try:
        await _converge(session, case_id, ended=ended, reversal_settled=reversal_settled)
    finally:
        session.info.pop(_CONVERGING, None)


async def _converge(session: AsyncSession, case_id: uuid.UUID, *, ended: bool, reversal_settled: bool) -> None:
    case = (
        await session.execute(select(CorrelationCase).where(CorrelationCase.id == case_id).with_for_update())
    ).scalar_one_or_none()
    if case is None:
        return
    wanted = _wanted(case, datetime.now(UTC))
    findings: dict[uuid.UUID, Finding] = {finding.id: finding for finding in await _members(session, case)}
    by_finding: dict[uuid.UUID, list[ActionRequest]] = {}
    for request in await _suppression_requests(session, case):
        finding_id, _ = _parse_suppression_key(request.idempotency_key)
        if finding_id not in findings:
            orphan = await session.get(Finding, finding_id)
            if orphan is None:
                _log.warning("suppression request %s names a missing finding; cannot reverse it", request.id)
                continue
            findings[finding_id] = orphan
        by_finding.setdefault(finding_id, []).append(request)
    blocking = False
    settled = False
    for finding_id in sorted(findings):
        finding_blocking, finding_settled = await _converge_finding(
            session, case, findings[finding_id], by_finding.get(finding_id, []), wanted
        )
        blocking = blocking or finding_blocking
        settled = settled or finding_settled
    if not blocking and wanted is None and (ended or reversal_settled or settled):
        await _enqueue_reconcile(session, case, list(findings.values()))


async def on_exception_decision(
    session: AsyncSession, connection: Connection, record: SourceRecord
) -> CorrelationCase | None:
    """Apply an Archer exception decision to the matching case. Invalid blocks change nothing.

    A decision for a case that does not exist yet is dropped. The full sync that follows any
    decision is the recovery path, so nothing is replayed here.
    """
    decision = _parse_decision(record)
    if decision is None:
        _log.warning("exception decision block absent or invalid; no state change (uid=%s)", record.uid)
        return None
    case = (
        await session.execute(
            select(CorrelationCase)
            .where(
                CorrelationCase.tenant_id == connection.tenant_id,
                CorrelationCase.correlation_key == decision.correlation_key,
                CorrelationCase.merged_into.is_(None),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if case is None:
        _log.warning("exception decision for unknown case; dropped (key=%s)", decision.correlation_key)
        return None
    previous = case.exception_state
    now = datetime.now(UTC)
    state = decision.status
    expires_at = decision.expires_at if decision.status == "approved" else None
    if state == "approved" and (expires_at is None or expires_at <= now):
        state = "expired"
    case.exception_state = state
    case.exception_revision = decision.revision
    case.exception_scope_uids = sorted(decision.scope_uids)
    case.exception_expires_at = expires_at
    if previous != state:
        await case_event(session, case)
    if state == "approved":
        await _schedule_expiry(session, case)
    await converge_case(session, case.id, ended=previous != state and state in {"rejected", "expired"})
    return case


async def converge_after_terminal(session: AsyncSession, request: ActionRequest) -> None:
    """Re-converge the case after an F3 action reaches a terminal state (tickets hook entry point)."""
    if request.correlation_id is None:
        return
    await converge_case(
        session,
        uuid.UUID(request.correlation_id),
        reversal_settled=request.state in _REVERSED and request.idempotency_key.startswith(_REVERSE_PREFIX),
    )


async def run_exception_expiry_job(payload: dict[str, Any], lease: Any = None) -> dict[str, int]:
    """Expire an approval at its scheduled instant. Stale jobs are no-ops; early jobs rearm."""
    tenant_id = uuid.UUID(payload["tenant_id"])
    case_id = uuid.UUID(payload["case_id"])
    scheduled_for = datetime.fromisoformat(payload["scheduled_for"])
    async with session_scope(tenant_id) as session:
        case = (
            await session.execute(select(CorrelationCase).where(CorrelationCase.id == case_id).with_for_update())
        ).scalar_one_or_none()
        if case is None or case.exception_state != "approved" or case.exception_expires_at != scheduled_for:
            return {"expired": 0}
        if scheduled_for > datetime.now(UTC):
            await _schedule_expiry(session, case, rearm=True)
            return {"expired": 0}
        case.exception_state = "expired"
        await case_event(session, case)
        await converge_case(session, case.id, ended=True)
        return {"expired": 1}


JOB_HANDLERS = {EXPIRY_KIND: run_exception_expiry_job}
