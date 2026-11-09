"""Postgres job queue with leases and fenced lease mutations (ADR-0014).

Lifecycle of a ``job`` row, tracked in ``state``:

- ``queued``: eligible once ``run_at <= now()``. A scheduled retry is a ``queued`` row with a
  future ``run_at``, so the partial unique index ``uq_job_dedupe_active`` covers retries too.
- ``running``: claimed. ``lease_id``, ``lease_owner`` and ``lease_expires_at`` are set.
- ``completed``: terminal success. Results are not persisted: the table has no result column.
- ``dead``: terminal failure once ``attempts >= max_attempts``. The row is kept with its payload
  and ``last_error``.

Every lease mutation matches on ``id``, ``lease_id`` and ``state = 'running'``. Zero affected rows
raises :class:`LeaseLost`. Database ``now()`` decides eligibility and lease expiry, so worker
clocks do not affect correctness.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.storage.db import admin_session
from icuhub.storage.models import Job

__all__ = [
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_PRIORITY",
    "DuplicateActiveJob",
    "InvalidJob",
    "JobState",
    "Lease",
    "LeaseLost",
    "QueueError",
    "RecoveryResult",
    "claim",
    "complete",
    "enqueue",
    "heartbeat",
    "recover_expired",
    "retry",
]

DEFAULT_PRIORITY = 100
"""Default ``job.priority``. Lower values are claimed first."""

DEFAULT_MAX_ATTEMPTS = 5
"""Default ``job.max_attempts``. Each claim counts as one attempt."""

_BACKOFF_BASE = timedelta(seconds=5)
_BACKOFF_CAP = timedelta(hours=1)
_MAX_BACKOFF_EXPONENT = 16  # 5 s * 2**16 already exceeds the cap, so larger exponents add nothing
_NAME_MAX = 64
_DEDUPE_KEY_MAX = 300
_OWNER_MAX = 200
_PRIORITY_MIN = -32768  # PostgreSQL smallint range
_PRIORITY_MAX = 32767
_LEASE_EXPIRED_ERROR = "lease expired before completion"
_RELEASED: dict[str, Any] = {"lease_id": None, "lease_owner": None, "lease_expires_at": None}


class JobState(StrEnum):
    """Values of ``job.state``."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    DEAD = "dead"


_ACTIVE_STATES = (JobState.QUEUED, JobState.RUNNING)


class QueueError(Exception):
    """Base class for job queue failures."""


class InvalidJob(QueueError):  # noqa: N818  # name pinned by tests/core/test_queue.py
    """A queue argument violates the queue contract."""


class DuplicateActiveJob(QueueError):  # noqa: N818  # name pinned by tests/core/test_queue.py
    """An active job (queued or running, including scheduled retries) already holds the dedupe key."""

    def __init__(self, dedupe_key: str, existing_job_id: uuid.UUID) -> None:
        super().__init__(f"active job {existing_job_id} already holds dedupe key {dedupe_key!r}")
        self.dedupe_key = dedupe_key
        self.existing_job_id = existing_job_id


class LeaseLost(QueueError):  # noqa: N818  # name pinned by tests/core/test_queue.py
    """The lease is no longer held: it expired and was recovered, reclaimed, or already finished."""

    def __init__(self, job_id: uuid.UUID, lease_id: uuid.UUID) -> None:
        super().__init__(f"lease {lease_id} on job {job_id} is no longer held")
        self.job_id = job_id
        self.lease_id = lease_id


@dataclass(frozen=True, slots=True)
class Lease:
    """A claimed job as seen by its worker. Pass it back to heartbeat, complete, or retry."""

    job_id: uuid.UUID
    lease_id: uuid.UUID
    tenant_id: uuid.UUID | None
    queue: str
    kind: str
    payload: dict[str, Any]
    attempt: int
    max_attempts: int
    owner: str
    expires_at: datetime
    ttl: timedelta


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    """Rows changed by one :func:`recover_expired` sweep."""

    requeued: int
    dead: int


def _require_text(field: str, value: object, max_length: int | None = None) -> None:
    if not isinstance(value, str) or not value or (max_length is not None and len(value) > max_length):
        bound = "" if max_length is None else f" of at most {max_length} characters"
        raise InvalidJob(f"{field} must be a non-empty string{bound}")


def _require_ttl(ttl: timedelta) -> None:
    if ttl <= timedelta(0):
        raise InvalidJob("ttl must be positive")


def _fence(lease: Lease) -> tuple[Any, ...]:
    return (Job.id == lease.job_id, Job.lease_id == lease.lease_id, Job.state == JobState.RUNNING)


def _backoff_delay(attempt: int) -> timedelta:
    exponent = min(attempt - 1, _MAX_BACKOFF_EXPONENT)
    return min(_BACKOFF_BASE * (2**exponent), _BACKOFF_CAP)


async def _active_job_id(session: AsyncSession, dedupe_key: str) -> uuid.UUID | None:
    return await session.scalar(
        select(Job.id).where(Job.dedupe_key == dedupe_key, Job.state.in_(_ACTIVE_STATES)).limit(1)
    )


async def enqueue(
    session: AsyncSession,
    queue: str,
    kind: str,
    payload: dict[str, Any],
    *,
    tenant_id: uuid.UUID | None,
    run_at: datetime | None = None,
    dedupe_key: str | None = None,
    priority: int = DEFAULT_PRIORITY,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> uuid.UUID:
    """Insert a queued job inside the caller's transaction and return its id.

    ``run_at`` defaults to the database ``now()``. A ``dedupe_key`` that matches a queued, running,
    or scheduled-retry job raises :class:`DuplicateActiveJob`; completed and dead history does not
    block reuse. Concurrent inserts are serialised by ``uq_job_dedupe_active``; the loser sees the
    unique violation and reports :class:`DuplicateActiveJob`.
    """
    _require_text("queue", queue, _NAME_MAX)
    _require_text("kind", kind, _NAME_MAX)
    if not isinstance(payload, dict):
        raise InvalidJob("payload must be a JSON object")
    if run_at is not None and run_at.tzinfo is None:
        raise InvalidJob("run_at must be timezone-aware")
    if dedupe_key is not None:
        _require_text("dedupe_key", dedupe_key, _DEDUPE_KEY_MAX)
    if not _PRIORITY_MIN <= priority <= _PRIORITY_MAX:
        raise InvalidJob(f"priority must be between {_PRIORITY_MIN} and {_PRIORITY_MAX}")
    if max_attempts < 1:
        raise InvalidJob("max_attempts must be at least 1")

    if dedupe_key is not None:
        existing = await _active_job_id(session, dedupe_key)
        if existing is not None:
            raise DuplicateActiveJob(dedupe_key, existing)

    job_id = uuid.uuid4()
    job = Job(
        id=job_id,
        tenant_id=tenant_id,
        queue=queue,
        kind=kind,
        payload_json=payload,
        priority=priority,
        run_at=func.now() if run_at is None else run_at,
        attempts=0,
        max_attempts=max_attempts,
        state=JobState.QUEUED,
        dedupe_key=dedupe_key,
    )
    try:
        async with session.begin_nested():
            session.add(job)
            await session.flush()
    except IntegrityError as exc:
        if dedupe_key is None:
            raise
        existing = await _active_job_id(session, dedupe_key)
        if existing is None:
            raise
        raise DuplicateActiveJob(dedupe_key, existing) from exc
    return job_id


async def claim(queue_names: Sequence[str], owner: str, ttl: timedelta) -> Lease | None:
    """Claim one eligible job from ``queue_names`` and return its lease, or ``None`` if none is free.

    Eligible means ``state = 'queued'`` and ``run_at <= now()``. Candidates are ordered by the number
    of running jobs their tenant already holds (fewest first), then ``priority``, ``run_at`` and
    ``id``. The row is locked with ``FOR UPDATE SKIP LOCKED``, so concurrent claimers never receive
    the same job and do not wait on each other. Attempts are incremented here, not on retry.
    """
    queues = list(queue_names)
    if not queues:
        raise InvalidJob("queue_names must not be empty")
    for name in queues:
        _require_text("queue name", name, _NAME_MAX)
    _require_text("owner", owner, _OWNER_MAX)
    _require_ttl(ttl)

    running = (
        select(Job.tenant_id.label("tenant_id"), func.count().label("running_count"))
        .where(Job.queue.in_(queues), Job.state == JobState.RUNNING)
        .group_by(Job.tenant_id)
        .subquery("running")
    )
    # The pick is a scalar subquery compared with ``=``. An ``IN (... FOR UPDATE ... LIMIT 1)`` form
    # lets Postgres apply the row lock to the outer UPDATE and updates every queued row. correlate(None)
    # keeps the inner ``job`` from being correlated to the UPDATE target of the same table.
    eligible = (
        select(Job.id)
        .select_from(Job)
        .outerjoin(running, running.c.tenant_id.is_not_distinct_from(Job.tenant_id))
        .where(Job.queue.in_(queues), Job.state == JobState.QUEUED, Job.run_at <= func.now())
        .order_by(func.coalesce(running.c.running_count, 0), Job.priority, Job.run_at, Job.id)
        .with_for_update(of=Job, skip_locked=True)
        .limit(1)
        .correlate(None)
        .scalar_subquery()
    )
    lease_id = uuid.uuid4()
    stmt = (
        update(Job)
        .where(Job.id == eligible, Job.state == JobState.QUEUED)
        .values(
            state=JobState.RUNNING,
            attempts=Job.attempts + 1,
            lease_id=lease_id,
            lease_owner=owner,
            lease_expires_at=func.now() + ttl,
        )
        .returning(
            Job.id,
            Job.tenant_id,
            Job.queue,
            Job.kind,
            Job.payload_json,
            Job.attempts,
            Job.max_attempts,
            Job.lease_expires_at,
        )
        .execution_options(synchronize_session=False)
    )
    async with admin_session() as session:
        row = (await session.execute(stmt)).one_or_none()
    if row is None:
        return None
    return Lease(
        job_id=row.id,
        lease_id=lease_id,
        tenant_id=row.tenant_id,
        queue=row.queue,
        kind=row.kind,
        payload=row.payload_json,
        attempt=row.attempts,
        max_attempts=row.max_attempts,
        owner=owner,
        expires_at=row.lease_expires_at,
        ttl=ttl,
    )


async def heartbeat(lease: Lease) -> Lease:
    """Extend the lease by its ttl from database ``now()``. Returns the lease with its new expiry.

    An expired lease cannot be extended, even before :func:`recover_expired` has released it.
    """
    stmt = (
        update(Job)
        .where(*_fence(lease), Job.lease_expires_at > func.now())
        .values(lease_expires_at=func.now() + lease.ttl)
        .returning(Job.lease_expires_at)
        .execution_options(synchronize_session=False)
    )
    async with admin_session() as session:
        expires_at = (await session.execute(stmt)).scalar_one_or_none()
    if expires_at is None:
        raise LeaseLost(lease.job_id, lease.lease_id)
    return replace(lease, expires_at=expires_at)


async def complete(lease: Lease) -> None:
    """Mark the leased job completed and release the lease.

    No result is persisted: the job table has no result column, and the schema is frozen.
    """
    stmt = (
        update(Job)
        .where(*_fence(lease))
        .values(state=JobState.COMPLETED, **_RELEASED)
        .returning(Job.id)
        .execution_options(synchronize_session=False)
    )
    async with admin_session() as session:
        fenced_id = (await session.execute(stmt)).scalar_one_or_none()
    if fenced_id is None:
        raise LeaseLost(lease.job_id, lease.lease_id)


async def retry(lease: Lease, error: str, delay: timedelta | None = None) -> JobState:
    """Record ``error`` and release the lease. Returns the resulting state.

    If ``lease.attempt`` has reached ``lease.max_attempts`` the job becomes ``dead`` and its row is
    kept. Otherwise it becomes ``queued`` with ``run_at = now() + delay``. When ``delay`` is ``None``
    the delay is exponential backoff from 5 s, doubling per attempt and capped at one hour.
    """
    _require_text("error", error)
    if delay is not None and delay < timedelta(0):
        raise InvalidJob("delay must not be negative")

    schedule: dict[str, Any]
    if lease.attempt >= lease.max_attempts:
        next_state = JobState.DEAD
        schedule = {}
    else:
        next_state = JobState.QUEUED
        wait = delay if delay is not None else _backoff_delay(lease.attempt)
        schedule = {"run_at": func.now() + wait}
    stmt = (
        update(Job)
        .where(*_fence(lease))
        .values(state=next_state, last_error=error, **schedule, **_RELEASED)
        .returning(Job.id)
        .execution_options(synchronize_session=False)
    )
    async with admin_session() as session:
        fenced_id = (await session.execute(stmt)).scalar_one_or_none()
    if fenced_id is None:
        raise LeaseLost(lease.job_id, lease.lease_id)
    return next_state


async def recover_expired() -> RecoveryResult:
    """Release every running job whose lease has expired.

    Jobs with attempts left return to ``queued`` with ``run_at = now()``. Exhausted jobs become
    ``dead``. Neither path deletes a row, and attempts are not incremented here. A worker that
    presents its old lease afterwards gets :class:`LeaseLost`.
    """
    expired = (Job.state == JobState.RUNNING, Job.lease_expires_at <= func.now())
    dead_stmt = (
        update(Job)
        .where(*expired, Job.attempts >= Job.max_attempts)
        .values(state=JobState.DEAD, last_error=_LEASE_EXPIRED_ERROR, **_RELEASED)
        .returning(Job.id)
        .execution_options(synchronize_session=False)
    )
    requeue_stmt = (
        update(Job)
        .where(*expired, Job.attempts < Job.max_attempts)
        .values(state=JobState.QUEUED, run_at=func.now(), last_error=_LEASE_EXPIRED_ERROR, **_RELEASED)
        .returning(Job.id)
        .execution_options(synchronize_session=False)
    )
    async with admin_session() as session:
        dead = len((await session.execute(dead_stmt)).scalars().all())
        requeued = len((await session.execute(requeue_stmt)).scalars().all())
    return RecoveryResult(requeued=requeued, dead=dead)
