"""Flow F1 end to end: scan -> correlate -> route -> approve -> apply -> status -> audit.

All vendor I/O is recorded; Postgres is real. This is the MVP smoke scenario.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from sqlalchemy import select

from icuhub.core.actions import decide
from icuhub.core.audit import verify_chain
from icuhub.core.sync import trigger_sync
from icuhub.kit.types import TicketRecord
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionRequest,
    Approval,
    CorrelationCase,
    Finding,
    Job,
    Tenant,
    TicketLink,
    TicketRoute,
)
from icuhub.workers.main import run_once
from tests.core.helpers import caller_for, finding, make_services, new_connection, vendor_transport


def test_f1_scan_to_ticket_to_done(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": [], "findings": [finding("flow-1"), finding("flow-2")]}
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
                    name="high",
                    connection_id=tracker.id,
                    action="create_issue",
                    match_json={"min_severity_id": 4},
                    template_json={"labels": ["security"]},
                )
            )
            await session.flush()
            await trigger_sync(session, caller_for(tenant_id), scanner.id, "findings")
        assert await run_once(queues=("sync", "tickets"), max_jobs=10) >= 2
        async with session_scope(tenant_id) as session:
            case = (await session.execute(select(CorrelationCase))).scalars().one()
            members = (await session.execute(select(Finding))).scalars().all()
            assert len(members) == 2
            link = (await session.execute(select(TicketLink))).scalars().one()
            request = (await session.execute(select(ActionRequest))).scalars().one()
            approval = (await session.execute(select(Approval))).scalar_one()
            await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
            assert request.state == "approved"
            apply_job = (
                await session.execute(select(Job).where(Job.kind == "apply", Job.state == "queued"))
            ).scalars().one()
            assert apply_job.payload_json["tenant_id"] == str(tenant_id)
        assert await run_once(queues=("actions",), max_jobs=5) == 1
        async with session_scope(tenant_id) as session:
            link = (await session.execute(select(TicketLink))).scalars().one()
            assert link.remote_key == "ISSUE-1"
            assert link.state == "succeeded"
            assert len(state["issues"]) == 1
            from icuhub.core.tickets import on_ticket_record  # noqa: PLC0415

            await on_ticket_record(
                session,
                tracker,
                TicketRecord(
                    uid="ISSUE-1",
                    key="ISSUE-1",
                    status="Done",
                    status_category="done",
                    revision="inbound-1",
                    data={},
                ),
            )
            case = await session.get(CorrelationCase, case.id)
            assert case.remediation_state == "done"
            for row in (await session.execute(select(Finding))).scalars().all():
                assert row.status != "resolved_by_source"
            verdict = await verify_chain(session, tenant_id)
            assert verdict.ok and verdict.checked > 0

    asyncio.run(scenario())
