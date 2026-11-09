"""Cross-vendor routing: one ticket per (route, case), status sync, echo suppression."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from sqlalchemy import select

from icuhub.core.actions import decide, run_apply_job
from icuhub.core.correlation import correlation_key, link_finding
from icuhub.core.tickets import evaluate_routes, on_ticket_record
from icuhub.kit.types import TicketRecord
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionRequest,
    Approval,
    Connection,
    CorrelationCase,
    Finding,
    Tenant,
    TicketLink,
    TicketRoute,
)
from tests.core.helpers import caller_for, finding, make_services, new_connection, vendor_transport


async def _finding_row(connection: Connection, uid: str, severity: int = 4) -> Finding:
    raw = finding(uid)
    document = {
        "class_uid": 2002,
        "finding_info": {"uid": uid, "title": raw["title"]},
        "vulnerabilities": [
            {
                "cve": {"uid": raw["cve"]},
                "affected_packages": [{"name": "requests", "purl": raw["purl"], "version": "2.31.0"}],
            }
        ],
        "resources": [{"uid": raw["purl"]}],
        "severity_id": severity,
    }
    row = Finding(
        tenant_id=connection.tenant_id,
        connection_id=connection.id,
        stream="findings",
        source_uid=uid,
        fingerprint=f"fp-{uid}",
        ocsf_class_uid=2002,
        severity_id=severity,
        title=raw["title"],
        ocsf_json=document,
        revision_digest=f"rev-{uid}",
        mapper_version=1,
    )
    assert correlation_key(document, connector_kind=connection.kind)[0]
    return row


def test_one_ticket_per_case_status_and_echo(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state: dict[str, Any] = {"issues": []}
        services = make_services(vendor_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            scanner = await new_connection(session, services, tenant_id, kind="sample_scanner")
            other = await new_connection(session, services, tenant_id, kind="sample_scanner_b")
            tracker = await new_connection(session, services, tenant_id, kind="sample_tracker_core")
            route = TicketRoute(
                tenant_id=tenant_id,
                name="high-cves",
                connection_id=tracker.id,
                action="create_issue",
                match_json={"min_severity_id": 4},
                template_json={"labels": ["icuhub"], "priority": "High"},
            )
            session.add(route)
            first = await _finding_row(scanner, "obs-a")
            second = await _finding_row(other, "obs-b")
            session.add_all([first, second])
            await session.flush()
            case = await link_finding(session, first)
            same = await link_finding(session, second)
            assert same.id == case.id, "two vendors must share one case"
            created = await evaluate_routes(session, case)
            assert len(created) == 1
            assert (await session.execute(select(TicketLink))).scalars().one().state == "pending_approval"
            request = (await session.execute(select(ActionRequest))).scalars().one()
            approval = (await session.execute(select(Approval))).scalar_one()
            await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
            assert request.state == "approved"
        async with session_scope(tenant_id) as session:
            result = await run_apply_job({"action_request_id": str(request.id), "tenant_id": str(tenant_id)})
            assert result["state"] == "succeeded"
            link = (await session.execute(select(TicketLink))).scalars().one()
            assert link.remote_key == "ISSUE-1"
            assert link.state == "succeeded"
            assert len(state["issues"]) == 1
            created_again = await evaluate_routes(session, await session.get(CorrelationCase, case.id))
            assert created_again == [], "second evaluation must not create a second ticket"
        async with session_scope(tenant_id) as session:
            link = (await session.execute(select(TicketLink))).scalars().one()
            outbound = link.last_outbound_revision
            inbound = TicketRecord(
                uid="ISSUE-1",
                key="ISSUE-1",
                revision="rev-2",
                status="Done",
                status_category="done",
                resolution="Fixed",
                data={"summary": "ICUHub case"},
            )
            await on_ticket_record(session, tracker, inbound)
            refreshed_case = await session.get(CorrelationCase, case.id)
            assert refreshed_case.remediation_state == "done"
            finding_row = await session.get(Finding, first.id)
            assert finding_row.status != "resolved_by_source", "ticket close never changes detection state"
            unchanged = await session.get(TicketLink, link.id)
            assert unchanged.last_inbound_revision == "rev-2"
            echo = TicketRecord(
                uid="ISSUE-1",
                key="ISSUE-1",
                revision=outbound,
                status="Open",
                status_category="open",
                data={"summary": "x"},
            )
            await on_ticket_record(session, tracker, echo)
            still = await session.get(CorrelationCase, case.id)
            assert still.remediation_state == "done", "echo must be suppressed"
    asyncio.run(scenario())
