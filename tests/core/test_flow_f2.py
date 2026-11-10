"""F2: authority-mapped Jira triage drives one governed source action."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from icuhub.core.actions import decide
from icuhub.core.correlation import link_finding
from icuhub.core.sync import trigger_sync
from icuhub.kit.connector import action
from icuhub.kit.errors import StalePlan
from icuhub.kit.testing import RouteTransport
from icuhub.kit.types import ActionOutcome, ActionPlan
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionRequest,
    Approval,
    CorrelationCase,
    Finding,
    Tenant,
    TicketLink,
    TicketRoute,
)
from icuhub.workers.main import run_once
from tests.core.helpers import REGISTRY, caller_for, make_services, new_connection
from tests.core.sample.connector import SampleScanner


class SuppressionArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_uid: str
    revision: str
    suppressed: bool


class FlowSource(SampleScanner):
    """Narrow vendor double with revision-checked suppression."""

    kind: ClassVar[str] = "flow_source_f2"

    @action(
        "set_suppression",
        classification="write",
        capability="FindingSource",
        input_model=SuppressionArgs,
        idempotency="natural_key",
    )
    async def plan_suppression(self, args: SuppressionArgs) -> ActionPlan:
        current = (await self.http.request("GET", f"/api/source/{args.source_uid}")).json()
        if current["revision"] != args.revision:
            raise StalePlan("source revision changed")
        return ActionPlan(
            action="set_suppression",
            target_ref=f"flow-source:{args.source_uid}",
            diff={"suppressed": {"from": current["suppressed"], "to": args.suppressed}},
            preconditions={"revision": current["revision"]},
            idempotency_key=f"suppression:{args.source_uid}:{args.revision}:{args.suppressed}",
            changed=current["suppressed"] != args.suppressed,
            request={
                "source_uid": args.source_uid,
                "expected_revision": current["revision"],
                "suppressed": args.suppressed,
            },
        )

    @plan_suppression.apply
    async def apply_suppression(self, plan: ActionPlan) -> ActionOutcome:
        uid = str(plan.request["source_uid"])
        current = (await self.http.request("GET", f"/api/source/{uid}")).json()
        if current["revision"] != plan.preconditions["revision"]:
            raise StalePlan("source revision changed")
        response = await self.http.request(
            "POST",
            f"/api/source/{uid}",
            json={
                "expected_revision": plan.request["expected_revision"],
                "suppressed": plan.request["suppressed"],
            },
        )
        return ActionOutcome(status="succeeded", vendor_ref=uid, result=response.json())


def _transport(state: dict[str, Any]) -> RouteTransport:
    def read_source(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": dict(state["source"])}

    def write_source(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        assert body["expected_revision"] == state["source"]["revision"]
        state["writes"] += 1
        state["source"]["suppressed"] = body["suppressed"]
        state["source"]["revision"] = str(int(state["source"]["revision"]) + 1)
        return {"status": 200, "json": dict(state["source"])}

    return RouteTransport(
        {
            ("GET", "/api/ping"): {"status": 200, "json": {"ok": True}},
            ("GET", "/api/tickets"): lambda request: {"status": 200, "json": {"items": state["tickets"]}},
            ("GET", "/api/source/alert-1"): read_source,
            ("POST", "/api/source/alert-1"): write_source,
        }
    )


def test_jira_triage_has_one_governed_write_and_no_ping_pong(
    tmp_path: Any, clean_database: None, monkeypatch: Any
) -> None:
    monkeypatch.setitem(REGISTRY, FlowSource.kind, FlowSource)

    async def scenario() -> None:
        state: dict[str, Any] = {
            "writes": 0,
            "source": {"revision": "7", "suppressed": False},
            "tickets": [
                {
                    "key": "ISSUE-1",
                    "status": "Done",
                    "status_category": "done",
                    "revision": "jira-1",
                }
            ],
        }
        services = make_services(_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            source = await new_connection(session, services, tenant_id, kind=FlowSource.kind)
            tracker = await new_connection(session, services, tenant_id, kind="sample_tracker_core")
            finding = Finding(
                tenant_id=tenant_id,
                connection_id=source.id,
                stream="findings",
                source_uid="alert-1",
                fingerprint="fp-alert-1",
                ocsf_class_uid=2002,
                severity_id=4,
                status="open",
                title="Prisma alert",
                ocsf_json={
                    "class_uid": 2002,
                    "finding_info": {"uid": "alert-1", "title": "Prisma alert"},
                    "unmapped": {"revision": "7"},
                },
                revision_digest="source-revision-7",
                mapper_version=1,
            )
            session.add(finding)
            await session.flush()
            case = await link_finding(session, finding)
            route = TicketRoute(
                tenant_id=tenant_id,
                name="jira-risk-authority",
                connection_id=tracker.id,
                action="create_issue",
                match_json={},
                template_json={},
                status_policy_json={
                    "source_action": {
                        "connection_id": str(source.id),
                        "action": "set_suppression",
                        "mapping_version": "jira-suppression-v1",
                        "status_categories": ["done"],
                        "source_revision_path": "unmapped.revision",
                        "args": {
                            "source_uid": "{source_uid}",
                            "revision": "{source_revision}",
                            "suppressed": True,
                        },
                    }
                },
            )
            session.add(route)
            await session.flush()
            session.add(
                TicketLink(
                    tenant_id=tenant_id,
                    route_id=route.id,
                    case_id=case.id,
                    connection_id=tracker.id,
                    state="succeeded",
                    remote_key="ISSUE-1",
                    remote_id="ISSUE-1",
                )
            )
            await session.flush()
            await trigger_sync(session, caller_for(tenant_id), tracker.id, "tickets")
            case_id = case.id
            route_id = route.id
            finding_id = finding.id
            tracker_id = tracker.id

        assert await run_once(queues=("sync",), max_jobs=1) == 1
        async with session_scope(tenant_id) as session:
            request = (await session.execute(select(ActionRequest))).scalars().one()
            assert request.action == "set_suppression"
            assert request.state == "pending_approval"
            assert request.correlation_id == str(case_id)
            approval = (await session.execute(select(Approval))).scalar_one()
            assert state["writes"] == 0
            await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
            request_id = request.id

        assert await run_once(queues=("actions",), max_jobs=1) == 1
        async with session_scope(tenant_id) as session:
            request = await session.get(ActionRequest, request_id)
            assert request is not None and request.state == "succeeded"
            result = (request.result_json or {}).get("result", {})
            assert result["revision"] == "8"
            assert state["writes"] == 1
            finding = await session.get(Finding, finding_id)
            assert finding is not None and finding.status == "open"
            case = await session.get(CorrelationCase, case_id)
            assert case is not None and case.detection_state == "open"
            link = (await session.execute(select(TicketLink))).scalar_one()
            assert link.last_inbound_revision == "jira-1"
            state["tickets"] = [
                {
                    "key": "ISSUE-1",
                    "status": "Done",
                    "status_category": "done",
                    "revision": "jira-2",
                }
            ]
            await trigger_sync(session, caller_for(tenant_id), tracker_id, "tickets")

        assert await run_once(queues=("sync",), max_jobs=1) == 1
        async with session_scope(tenant_id) as session:
            requests = (await session.execute(select(ActionRequest))).scalars().all()
            assert [row.id for row in requests] == [request_id]
            assert state["writes"] == 1
            route = await session.get(TicketRoute, route_id)
            assert route is not None
            state["tickets"] = [
                {
                    "key": "ISSUE-1",
                    "status": "Open",
                    "status_category": "open",
                    "revision": "jira-3",
                }
            ]
            await trigger_sync(session, caller_for(tenant_id), tracker_id, "tickets")

        assert await run_once(queues=("sync",), max_jobs=1) == 1
        async with session_scope(tenant_id) as session:
            assert len((await session.execute(select(ActionRequest))).scalars().all()) == 1
            assert state["writes"] == 1
            finding = await session.get(Finding, finding_id)
            assert finding is not None and finding.status == "open"

    asyncio.run(scenario())
