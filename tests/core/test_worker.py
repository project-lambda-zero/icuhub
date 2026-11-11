"""Worker loop smoke: real queue claims, scheduler, and the F1 chain through workers."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from icuhub.core.sync import scheduler_once, trigger_sync
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionRequest,
    Finding,
    Job,
    StreamState,
    Tenant,
    TicketLink,
    TicketRoute,
)
from icuhub.workers.main import run_once
from tests.core.helpers import caller_for, finding, make_services, new_connection, vendor_transport


def test_worker_processes_sync_and_route_jobs(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": [finding("w-1")]}
        services = make_services(vendor_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            scanner = await new_connection(session, services, tenant_id, kind="sample_scanner")
            tracker = await new_connection(session, services, tenant_id, kind="sample_tracker_core")
            session.add(
                TicketRoute(
                    tenant_id=tenant_id,
                    name="all",
                    connection_id=tracker.id,
                    action="create_issue",
                    match_json={"min_severity_id": 1},
                    template_json={},
                )
            )
            await session.flush()
            await trigger_sync(session, caller_for(tenant_id), scanner.id, "findings")
        processed = await run_once(queues=("sync", "tickets"), max_jobs=10)
        assert processed >= 2, "sync job and route job must both run"
        async with session_scope(tenant_id) as session:
            assert (await session.execute(select(Finding))).scalars().one()
            assert (await session.execute(select(TicketLink))).scalars().one()
            request = (await session.execute(select(ActionRequest))).scalars().one()
            assert request.state == "pending_approval"
            remaining = (
                await session.execute(select(Job).where(Job.state.in_(["queued", "running"])))
            ).scalars().all()
            apply_jobs = [j for j in remaining if j.kind == "apply"]
            assert not apply_jobs, "apply must wait for approval"
        processed_again = await run_once(queues=("sync", "tickets"), max_jobs=10)
        assert processed_again == 0

    asyncio.run(scenario())


def test_scheduler_enqueues_due_streams(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": [finding("w-2")]}
        services = make_services(vendor_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            scanner = await new_connection(session, services, tenant_id, kind="sample_scanner")
            await trigger_sync(session, caller_for(tenant_id), scanner.id, "findings")
        assert await run_once(queues=("sync",), max_jobs=5) == 1
        async with session_scope(tenant_id) as session:
            stream_state = (await session.execute(select(StreamState))).scalars().one()
            stream_state.next_run_at = datetime.now(UTC) - timedelta(seconds=1)
        scheduled = await scheduler_once()
        assert scheduled == 1
        async with session_scope(tenant_id) as session:
            jobs = (await session.execute(select(Job).where(Job.kind == "sync"))).scalars().all()
            assert len(jobs) == 2
        assert await run_once(queues=("sync",), max_jobs=5) == 1

    asyncio.run(scenario())
