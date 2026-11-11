"""Cross-vendor routing: one ticket per (route, case), status sync, echo suppression."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from icuhub.connectors._jira import mappers as jira_mappers
from icuhub.connectors._jira.models import CreateIssueInput
from icuhub.connectors.jira_cloud import JiraCloud
from icuhub.core.actions import decide, run_apply_job
from icuhub.core.correlation import correlation_key, link_finding
from icuhub.core.tickets import evaluate_routes, on_action_terminal, on_ticket_record
from icuhub.kit.testing import RouteTransport, make_connector
from icuhub.kit.types import MapContext, TicketRecord
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


def test_real_jira_create_revision_suppresses_f2_echo(tmp_path: Any, clean_database: None) -> None:
    updated = "2026-11-01T10:00:00.000+0000"
    raw_issue = {
        "id": "10050",
        "key": "PROJ-7",
        "self": "https://jira.example.test/rest/api/3/issue/10050",
        "fields": {
            "updated": updated,
            "status": {"name": "To Do", "statusCategory": {"key": "new"}},
        },
    }
    jira_connector = make_connector(
        JiraCloud,
        {
            "base_url": "https://jira.example.test",
            "auth_method": "basic",
            "account_email": "svc-automation@example.test",
            "api_token": {"ref": "jira-token"},
        },
        RouteTransport(
            {
                ("GET", "/rest/api/3/search/jql"): {"status": 200, "json": {"issues": []}},
                ("POST", "/rest/api/3/issue"): {
                    "status": 201,
                    "json": {"id": "10050", "key": "PROJ-7"},
                },
                ("GET", "/rest/api/3/issue/PROJ-7"): {"status": 200, "json": raw_issue},
            }
        ),
        {"jira-token": b"synthetic-jira-token"},
    )
    spec = JiraCloud.actions()["create_issue"]
    plan = asyncio.run(
        spec.plan(
            jira_connector,
            CreateIssueInput(
                route_key="route-jira-echo",
                project_key="PROJ",
                issue_type="Task",
                summary="Triage",
            ),
        )
    )
    outcome = asyncio.run(spec.apply(jira_connector, plan))
    assert outcome.status == "succeeded"
    assert outcome.result["revision"] == f"10050:{updated}"

    async def scenario() -> None:
        state: dict[str, Any] = {"issues": []}
        services = make_services(vendor_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            scanner = await new_connection(session, services, tenant_id, kind="sample_scanner")
            tracker = await new_connection(session, services, tenant_id, kind="sample_tracker_core")
            finding_row = await _finding_row(scanner, "obs-jira-echo")
            finding_row.ocsf_json["source_revision"] = "7"
            session.add(finding_row)
            await session.flush()
            case = await link_finding(session, finding_row)
            case.remediation_state = "done"
            route = TicketRoute(
                tenant_id=tenant_id,
                name="jira-echo-route",
                connection_id=tracker.id,
                action="create_issue",
                match_json={"min_severity_id": 4},
                template_json={},
                status_policy_json={
                    "source_action": {
                        "connection_id": str(tracker.id),
                        "action": "create_issue",
                        "args": {
                            "summary": "{source_uid}",
                            "route_key": "rk-f2-jira-echo",
                        },
                        "source_revision_path": "source_revision",
                        "status_categories": ["open"],
                        "mapping_version": "1",
                    }
                },
            )
            session.add(route)
            await session.flush()
            request = ActionRequest(
                tenant_id=tenant_id,
                connection_id=tracker.id,
                action="create_issue",
                classification="write",
                args_json={"route_key": "route-jira-echo"},
                args_digest=f"sha256:{'a' * 64}",
                caller_id="route:jira-echo-route",
                correlation_id=str(case.id),
                idempotency_key="jira-create-echo",
                state="succeeded",
                result_json=outcome.model_dump(mode="json"),
            )
            session.add(request)
            await session.flush()
            link = TicketLink(
                tenant_id=tenant_id,
                route_id=route.id,
                case_id=case.id,
                connection_id=tracker.id,
                state="succeeded",
                remote_status="Done",
                status_category="done",
                action_request_id=request.id,
            )
            session.add(link)
            await session.flush()
            await on_action_terminal(session, request)
            assert link.remote_key == "PROJ-7"
            assert link.last_outbound_revision == f"10050:{updated}"

            record = jira_mappers.map_issue(
                raw_issue,
                MapContext(
                    connection_id=str(tracker.id),
                    tenant_id=str(tenant_id),
                    connector_kind="jira_cloud",
                    received_at=datetime.now(UTC),
                ),
            )
            await on_ticket_record(session, tracker, record)
            assert link.last_inbound_revision == f"10050:{updated}"
            assert link.remote_status == "Done"
            assert link.status_category == "done"
            assert case.remediation_state == "done"
            requests = (await session.execute(select(ActionRequest))).scalars().all()
            assert [row.id for row in requests] == [request.id]
            assert state["issues"] == []

    asyncio.run(scenario())
