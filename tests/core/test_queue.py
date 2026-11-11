"""Behavioral tests for the Postgres job queue. Each test runs one scenario through asyncio.run."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Row, func, select

from icuhub.core.queue import (
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_PRIORITY,
    DuplicateActiveJob,
    InvalidJob,
    JobState,
    Lease,
    LeaseLost,
    RecoveryResult,
    claim,
    complete,
    enqueue,
    heartbeat,
    recover_expired,
    retry,
)
from icuhub.storage.db import admin_session
from icuhub.storage.models import Job, Tenant

LONG = timedelta(minutes=10)


async def _tenant(slug: str) -> uuid.UUID:
    tenant_id = uuid.uuid4()
    async with admin_session() as session:
        session.add(Tenant(id=tenant_id, slug=slug, display_name=slug))
    return tenant_id


async def _enqueue(tenant_id: uuid.UUID | None, *, queue: str = "sync", payload: Any = None, **kwargs: Any) -> uuid.UUID:
    async with admin_session() as session:
        return await enqueue(
            session,
            queue,
            "sync.run",
            payload if payload is not None else {"n": 1},
            tenant_id=tenant_id,
            **kwargs,
        )


async def _claim_one(queue: str = "sync", owner: str = "worker", ttl: timedelta = LONG) -> Lease:
    lease = await claim([queue], owner, ttl)
    assert lease is not None
    return lease


async def _snapshot(job_id: uuid.UUID) -> Row[Any]:
    stmt = select(
        Job.state,
        Job.attempts,
        Job.max_attempts,
        Job.priority,
        Job.last_error,
        Job.payload_json,
        Job.run_at,
        Job.lease_id,
        Job.lease_owner,
        Job.lease_expires_at,
    ).where(Job.id == job_id)
    async with admin_session() as session:
        return (await session.execute(stmt)).one()


async def _queue_states(queue: str) -> list[str]:
    stmt = select(Job.state).where(Job.queue == queue).order_by(Job.state)
    async with admin_session() as session:
        return list((await session.execute(stmt)).scalars().all())


async def _db_now() -> datetime:
    async with admin_session() as session:
        return await session.scalar(select(func.now()))


@pytest.mark.usefixtures("clean_database")
def test_enqueue_and_claim_expose_lease_fields() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-claim")
        job_id = await _enqueue(tenant_id)

        lease = await claim(["sync"], "worker-a", LONG)
        assert lease is not None
        assert lease.job_id == job_id
        assert lease.tenant_id == tenant_id
        assert lease.queue == "sync"
        assert lease.kind == "sync.run"
        assert lease.payload == {"n": 1}
        assert lease.attempt == 1
        assert lease.max_attempts == DEFAULT_MAX_ATTEMPTS
        assert lease.owner == "worker-a"
        assert lease.ttl == LONG
        assert lease.expires_at > await _db_now()

        row = await _snapshot(job_id)
        assert row.state == JobState.RUNNING
        assert row.attempts == 1
        assert row.priority == DEFAULT_PRIORITY
        assert row.lease_id == lease.lease_id
        assert row.lease_owner == "worker-a"

        assert await claim(["sync"], "worker-b", LONG) is None

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_claim_orders_by_priority_then_run_at_and_respects_eligibility() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-order")
        base = await _db_now()
        low = await _enqueue(tenant_id, queue="ord", priority=200, run_at=base - timedelta(seconds=300))
        newer_high = await _enqueue(tenant_id, queue="ord", priority=10, run_at=base - timedelta(seconds=100))
        older_high = await _enqueue(tenant_id, queue="ord", priority=10, run_at=base - timedelta(seconds=200))
        future = await _enqueue(tenant_id, queue="ord", priority=0, run_at=base + timedelta(hours=1))
        other = await _enqueue(tenant_id, queue="elsewhere", priority=0)

        claimed = [(await _claim_one(queue="ord")).job_id for _ in range(3)]
        assert claimed == [older_high, newer_high, low]
        assert await claim(["ord"], "worker", LONG) is None

        assert (await _snapshot(future)).state == JobState.QUEUED
        assert (await _snapshot(other)).state == JobState.QUEUED

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_active_dedupe_rejects_queued_running_and_scheduled_retry() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-dedupe")
        first = await _enqueue(tenant_id, dedupe_key="sync:acme:1")

        with pytest.raises(DuplicateActiveJob) as queued_error:
            await _enqueue(tenant_id, dedupe_key="sync:acme:1")
        assert queued_error.value.existing_job_id == first
        assert queued_error.value.dedupe_key == "sync:acme:1"

        lease = await _claim_one()
        with pytest.raises(DuplicateActiveJob):
            await _enqueue(tenant_id, dedupe_key="sync:acme:1")

        state = await retry(lease, "upstream 503", delay=timedelta(hours=1))
        assert state == JobState.QUEUED
        with pytest.raises(DuplicateActiveJob) as scheduled_error:
            await _enqueue(tenant_id, dedupe_key="sync:acme:1")
        assert scheduled_error.value.existing_job_id == first

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_dedupe_key_reusable_after_completion_and_death() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-reuse")
        dead_id = await _enqueue(tenant_id, dedupe_key="sync:acme:2", max_attempts=1)
        lease = await _claim_one()
        assert await retry(lease, "boom") == JobState.DEAD

        done_id = await _enqueue(tenant_id, dedupe_key="sync:acme:2")
        assert done_id != dead_id
        lease = await _claim_one()
        assert lease.job_id == done_id
        await complete(lease)

        reused_id = await _enqueue(tenant_id, dedupe_key="sync:acme:2")
        assert reused_id not in {dead_id, done_id}
        assert (await _snapshot(dead_id)).state == JobState.DEAD

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_concurrent_claimers_receive_distinct_jobs() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-concurrent")
        job_ids: set[uuid.UUID] = set()
        for _ in range(10):
            job_ids.add(await _enqueue(tenant_id))

        leases = await asyncio.gather(*(claim(["sync"], f"worker-{i}", LONG) for i in range(10)))
        claimed = [lease for lease in leases if lease is not None]
        assert len(claimed) == 10
        assert {lease.job_id for lease in claimed} == job_ids
        assert len({lease.lease_id for lease in claimed}) == 10

        assert await _queue_states("sync") == [JobState.RUNNING] * 10

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_fairness_prefers_tenant_with_fewest_running_jobs() -> None:
    async def scenario() -> None:
        tenant_a = await _tenant("acme-fair-a")
        tenant_b = await _tenant("acme-fair-b")
        base = await _db_now()
        a1 = await _enqueue(tenant_a, run_at=base - timedelta(seconds=300))
        a2 = await _enqueue(tenant_a, run_at=base - timedelta(seconds=200))
        b1 = await _enqueue(tenant_b, run_at=base - timedelta(seconds=100))

        assert (await _claim_one()).job_id == a1
        assert (await _claim_one()).job_id == b1
        assert (await _claim_one()).job_id == a2

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_stale_lease_mutations_raise_lease_lost() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-stale")
        job_id = await _enqueue(tenant_id, queue="stale")

        stale = await claim(["stale"], "worker-a", timedelta(milliseconds=1))
        assert stale is not None
        await asyncio.sleep(0.05)
        assert await recover_expired() == RecoveryResult(requeued=1, dead=0)

        fresh = await claim(["stale"], "worker-b", LONG)
        assert fresh is not None
        assert fresh.job_id == job_id
        assert fresh.attempt == 2

        with pytest.raises(LeaseLost):
            await complete(stale)
        with pytest.raises(LeaseLost):
            await heartbeat(stale)
        with pytest.raises(LeaseLost):
            await retry(stale, "late")

        row = await _snapshot(job_id)
        assert row.state == JobState.RUNNING
        assert row.lease_id == fresh.lease_id
        assert row.attempts == 2
        assert row.payload_json == {"n": 1}
        assert row.last_error == "lease expired before completion"

        kept = await heartbeat(fresh)
        assert kept.lease_id == fresh.lease_id
        assert kept.expires_at > fresh.expires_at

        await complete(fresh)
        assert (await _snapshot(job_id)).state == JobState.COMPLETED

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_heartbeat_rejects_expired_lease_before_recovery() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-expired")
        job_id = await _enqueue(tenant_id, queue="hb")
        lease = await claim(["hb"], "worker-a", timedelta(milliseconds=1))
        assert lease is not None
        await asyncio.sleep(0.05)

        with pytest.raises(LeaseLost):
            await heartbeat(lease)

        row = await _snapshot(job_id)
        assert row.state == JobState.RUNNING
        assert row.lease_id == lease.lease_id

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_complete_releases_lease_without_persisting_result() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-complete")
        job_id = await _enqueue(tenant_id)
        lease = await _claim_one()

        await complete(lease)

        row = await _snapshot(job_id)
        assert row.state == JobState.COMPLETED
        assert row.payload_json == {"n": 1}
        assert row.lease_id is None
        assert row.lease_owner is None
        assert row.lease_expires_at is None

        with pytest.raises(LeaseLost):
            await complete(lease)

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_retry_immediate_then_dead_after_max_attempts() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-retry")
        job_id = await _enqueue(tenant_id, queue="retry", max_attempts=2)

        first = await _claim_one(queue="retry")
        assert await retry(first, "upstream 500", delay=timedelta(0)) == JobState.QUEUED

        second = await _claim_one(queue="retry")
        assert second.job_id == job_id
        assert second.attempt == 2
        assert await retry(second, "upstream 500") == JobState.DEAD

        row = await _snapshot(job_id)
        assert row.state == JobState.DEAD
        assert row.attempts == 2
        assert row.last_error == "upstream 500"
        assert row.payload_json == {"n": 1}
        assert row.lease_id is None
        assert row.lease_owner is None
        assert row.lease_expires_at is None
        assert await claim(["retry"], "worker", LONG) is None

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_retry_default_delay_is_exponential_backoff() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-backoff")
        job_id = await _enqueue(tenant_id, queue="backoff")
        lease = await _claim_one(queue="backoff")

        before = await _db_now()
        assert await retry(lease, "upstream 503") == JobState.QUEUED

        row = await _snapshot(job_id)
        assert row.state == JobState.QUEUED
        assert row.run_at - before >= timedelta(seconds=4)
        assert await claim(["backoff"], "worker", LONG) is None

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_expired_lease_recovery_requeues_without_deleting_and_kills_exhausted_jobs() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-recover")
        requeue_id = await _enqueue(tenant_id, queue="recover", max_attempts=3)
        dead_id = await _enqueue(tenant_id, queue="recover", max_attempts=1)

        leases = {
            lease.job_id: lease
            for lease in (
                await claim(["recover"], "worker-a", timedelta(milliseconds=1)),
                await claim(["recover"], "worker-b", timedelta(milliseconds=1)),
            )
            if lease is not None
        }
        assert set(leases) == {requeue_id, dead_id}
        await asyncio.sleep(0.05)

        assert await recover_expired() == RecoveryResult(requeued=1, dead=1)

        requeued = await _snapshot(requeue_id)
        assert requeued.state == JobState.QUEUED
        assert requeued.attempts == 1
        assert requeued.lease_id is None
        assert requeued.lease_owner is None
        assert requeued.lease_expires_at is None
        assert requeued.last_error == "lease expired before completion"
        assert requeued.payload_json == {"n": 1}

        dead = await _snapshot(dead_id)
        assert dead.state == JobState.DEAD
        assert dead.last_error == "lease expired before completion"
        assert dead.payload_json == {"n": 1}

        reclaimed = await _claim_one(queue="recover")
        assert reclaimed.job_id == requeue_id
        assert reclaimed.attempt == 2

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_enqueue_rejects_naive_run_at() -> None:
    async def scenario() -> None:
        async with admin_session() as session:
            with pytest.raises(InvalidJob):
                await enqueue(
                    session,
                    "sync",
                    "sync.run",
                    {"n": 1},
                    tenant_id=None,
                    run_at=datetime(2026, 1, 1),
                )

    asyncio.run(scenario())


@pytest.mark.usefixtures("clean_database")
def test_active_dedupe_race_is_reported_as_duplicate() -> None:
    async def scenario() -> None:
        tenant_id = await _tenant("acme-race")

        async def contender() -> uuid.UUID:
            return await _enqueue(tenant_id, dedupe_key="sync:race")

        async with admin_session() as session:
            first = await enqueue(session, "sync", "sync.run", {"n": 1}, tenant_id=tenant_id, dedupe_key="sync:race")
            blocked = asyncio.create_task(contender())
            await asyncio.sleep(0.3)
            assert not blocked.done()

        with pytest.raises(DuplicateActiveJob) as info:
            await blocked
        assert info.value.existing_job_id == first

    asyncio.run(scenario())
