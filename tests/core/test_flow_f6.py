"""F6 composition: OpenShift posture, governed remediation, async builds, and signed evidence."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from icuhub.connectors import CONNECTORS
from icuhub.connectors.archer import Archer
from icuhub.connectors.jira_cloud import JiraCloud
from icuhub.connectors.openshift import OpenShift
from icuhub.core.actions import decide, run_apply_job, run_reconcile_job, submit_action
from icuhub.core.auth_types import Caller
from icuhub.core.connections import create_connection
from icuhub.core.credentials import EncryptedBlob
from icuhub.core.evidence_export import EvidenceExportError, export_evidence_bundle, verify_evidence_bundle
from icuhub.core.services import configure
from icuhub.core.sync import trigger_sync
from icuhub.core.tickets import on_ticket_record
from icuhub.kit.http import httpx2
from icuhub.kit.testing import RouteTransport
from icuhub.kit.types import TicketRecord
from icuhub.settings import Settings
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionPlanRow,
    ActionRequest,
    Approval,
    AuditRecord,
    CaseMember,
    CorrelationCase,
    EvidenceItem,
    Finding,
    RawBatch,
    StreamState,
    Tenant,
    TicketLink,
    TicketRoute,
)
from icuhub.storage.models import (
    SourceRecord as SourceRecordRow,
)
from icuhub.workers.main import run_once

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "openshift" / "mappers"
ARCHER_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "archer" / "actions"
ARCHER_RECORD_TYPES = {
    "findings": {
        "application_id": 7,
        "level_id": 8,
        "field_ids": {
            "ExternalCorrelationId": 101,
            "Title": 102,
            "Evidence": 103,
            "Description": 104,
        },
        "correlation_field": "ExternalCorrelationId",
        "time_field": "LastUpdated",
    }
}
BASE_URL = "https://api.example.test"
JIRA_BASE = "https://jira.example.test"
APPROVED = "0" * 64
SCC_PATH = "/apis/security.openshift.io/v1/securitycontextconstraints/synthetic-restricted"
ROUTE_PATH = "/apis/route.openshift.io/v1/namespaces/orders/routes/synthetic-checkout"
BC_PATH = "/apis/build.openshift.io/v1/namespaces/orders/buildconfigs/web"
INSTANTIATE_PATH = f"{BC_PATH}/instantiate"
BUILDS_PATH = "/apis/build.openshift.io/v1/namespaces/orders/builds"


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _caller(tenant_id: uuid.UUID, name: str = "admin") -> Caller:
    return Caller(id=name, tenant_id=tenant_id, roles=frozenset({"admin"}), groups=frozenset({"secops"}))


def _approver(tenant_id: uuid.UUID) -> Caller:
    return Caller(id="approver", tenant_id=tenant_id, roles=frozenset({"approver"}), groups=frozenset({"secops"}))


def _services(tmp_path: Path, transport: RouteTransport) -> Any:
    kek_path = tmp_path / "kek"
    kek_path.write_bytes(bytes(range(32)))
    settings = Settings(
        database_url=os.environ["ICUHUB_DATABASE_URL"],
        kek_provider="file",
        kek_file_path=kek_path,
        automation_enabled=False,
    )
    return configure(settings, registry=CONNECTORS, transport=transport)


async def _connection(
    session: Any,
    services: Any,
    tenant_id: uuid.UUID,
    kind: str,
    config: dict[str, Any],
    secrets: dict[str, str],
) -> Any:
    return await create_connection(
        session,
        tenant_id,
        kind=kind,
        slug=f"{kind}-{uuid.uuid4().hex[:8]}",
        display_name=kind,
        config=config,
        secrets=secrets,
        caller=_caller(tenant_id),
        registry=CONNECTORS,
        broker=services.broker,
    )


def _openshift_config() -> dict[str, Any]:
    return {
        "base_url": BASE_URL,
        "cluster_name": "prod",
        "bearer_token": {"ref": "cluster-token"},
        "write_enabled": True,
        "destructive_enabled": True,
    }


async def _seed_openshift(
    services: Any, tenant_id: uuid.UUID, *, with_jira: bool = False
) -> tuple[Any, Any | None]:
    async with session_scope(tenant_id) as session:
        session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="F6"))
        await session.flush()
        cluster = await _connection(
            session, services, tenant_id, OpenShift.kind, _openshift_config(), {"bearer_token": "token"}
        )
        tracker = None
        if with_jira:
            tracker = await _connection(
                session,
                services,
                tenant_id,
                JiraCloud.kind,
                {
                    "base_url": JIRA_BASE,
                    "auth_method": "basic",
                    "account_email": "svc-automation@example.test",
                    "api_token": {"ref": "jira-token"},
                    "jql": "project = ICU",
                },
                {"api_token": "jira-secret"},
            )
            session.add(
                TicketRoute(
                    tenant_id=tenant_id,
                    name="openshift-findings",
                    connection_id=tracker.id,
                    action="create_issue",
                    match_json={"ocsf_class_uids": [2003]},
                    template_json={"project_key": "ICU", "issue_type": "Bug", "labels": ["posture"]},
                )
            )
        await session.flush()
        return cluster, tracker


async def _approve(session: Any, tenant_id: uuid.UUID, request: ActionRequest) -> Approval:
    approval = (
        await session.execute(select(Approval).where(Approval.action_request_id == request.id))
    ).scalar_one()
    await decide(session, _approver(tenant_id), approval.id, "approved", reason="F6 approved change")
    return approval


async def _submit(
    services: Any,
    tenant_id: uuid.UUID,
    connection: Any,
    action: str,
    args: dict[str, Any],
    *,
    correlation_id: str | None = None,
) -> ActionRequest:
    async with session_scope(tenant_id) as session:
        request = await submit_action(
            session,
            _caller(tenant_id),
            connection.id,
            action,
            args,
            idempotency_key=f"f6-{action}-{uuid.uuid4()}",
            correlation_id=correlation_id,
        )
        assert request.state == "pending_approval"
        await _approve(session, tenant_id, request)
        return request


def _writes(transport: RouteTransport, method: str, path: str) -> list[Any]:
    return [request for request in transport.requests if request.method == method and request.url.path == path]


async def _raw_json(services: Any, tenant_id: uuid.UUID, raw: RawBatch) -> Any:
    payload = await services.broker.decrypt_blob(
        tenant_id,
        raw.id,
        EncryptedBlob(
            kek_id=raw.kek_id,
            dek_wrapped=raw.dek_wrapped,
            nonce=raw.nonce,
            ciphertext=raw.payload_enc,
        ),
    )
    return json.loads(payload)


def _jira_routes(state: dict[str, Any]) -> dict[tuple[str, str], Any]:
    def create(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        key = f"ICU-{len(state['created']) + 1}"
        state["created"].append({"id": str(10000 + len(state["created"])), "key": key, "body": body})
        return {"status": 201, "json": {"id": state["created"][-1]["id"], "key": key}}

    def issue(_request: Any) -> dict[str, Any]:
        created = state["created"][0]
        return {
            "status": 200,
            "json": {
                "id": created["id"],
                "key": created["key"],
                "self": f"https://jira.example.test/rest/api/3/issue/{created['id']}",
                "fields": {
                    "updated": "2026-11-09T00:00:00.000+0000",
                    "status": {"name": "To Do", "statusCategory": {"key": "new"}},
                },
            },
        }

    return {
        ("GET", "/rest/api/3/myself"): {"status": 200, "json": {"accountId": "svc-automation"}},
        ("GET", "/rest/api/3/search/jql"): {"status": 200, "json": {"issues": [], "isLast": True}},
        ("GET", "/rest/api/3/issue/ICU-1"): issue,
        ("POST", "/rest/api/3/issue"): create,
    }


def _archer_routes(state: dict[str, Any]) -> dict[tuple[str, str], Any]:
    fields = json.loads((ARCHER_FIXTURES / "fields.json").read_text(encoding="utf-8"))
    fields.append({"IsSuccessful": True, "RequestedObject": {"Id": 104, "Name": "Description", "Type": 1}})

    def create(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        state["created"].append(body)
        return {"status": 201, "json": {"IsSuccessful": True, "RequestedObject": {"Id": 42}}}

    def read_back(_request: Any) -> dict[str, Any]:
        return {
            "status": 200,
            "json": {
                "IsSuccessful": True,
                "RequestedObject": {
                    "Id": 42,
                    "LevelId": 8,
                    "Version": 1,
                    "FieldContents": state["created"][-1]["Content"]["FieldContents"],
                },
            },
        }

    return {
        ("POST", "/platformapi/core/security/login"): {
            "status": 200,
            "json": {"IsSuccessful": True, "RequestedObject": {"SessionToken": "archer-session"}},
        },
        ("POST", "/ws/search.asmx"): {
            "status": 200,
            "text": (ARCHER_FIXTURES / "search_empty.xml").read_text(encoding="utf-8"),
        },
        ("POST", "/platformapi/core/system/fielddefinition/level/8"): {"status": 200, "json": fields},
        ("POST", "/platformapi/core/content"): create,
        ("POST", "/platformapi/core/content/contentid"): read_back,
    }


def _scc_routes(state: dict[str, Any]) -> dict[tuple[str, str], Any]:
    def patch(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        state["patch_bodies"].append(body)
        for key, value in body.items():
            if key != "metadata":
                state["scc"][key] = value
        state["scc"]["metadata"]["resourceVersion"] = "206"
        return {"status": 200, "json": state["scc"]}

    def listed(_request: Any) -> dict[str, Any]:
        return {
            "status": 200,
            "json": {
                "apiVersion": "security.openshift.io/v1",
                "kind": "SecurityContextConstraintsList",
                "metadata": {"resourceVersion": state["scc"]["metadata"]["resourceVersion"]},
                "items": [state["scc"]],
            },
        }

    return {
        ("GET", SCC_PATH): lambda _request: {"status": 200, "json": state["scc"]},
        ("PATCH", SCC_PATH): patch,
        ("GET", "/apis/security.openshift.io/v1/securitycontextconstraints"): listed,
    }


async def _open_compliance_case(tenant_id: uuid.UUID) -> tuple[Finding, CorrelationCase]:
    async with session_scope(tenant_id) as session:
        finding = (
            await session.execute(
                select(Finding).where(Finding.ocsf_class_uid == 2003, Finding.status == "open")
            )
        ).scalar_one()
        member = (
            await session.execute(select(CaseMember).where(CaseMember.finding_id == finding.id))
        ).scalar_one()
        case = await session.get(CorrelationCase, member.case_id)
        assert case is not None
        return finding, case


def test_f6_scc_posture_tracker_remediation_and_signed_evidence(
    tmp_path: Any, clean_database: None
) -> None:
    async def scenario() -> None:
        scc = _fixture("synthetic_scc_assessment.json")
        scc["allowPrivilegeEscalation"] = True
        state: dict[str, Any] = {"scc": scc, "created": [], "patch_bodies": []}
        transport = RouteTransport({**_scc_routes(state), **_jira_routes(state)})
        services = _services(tmp_path, transport)
        tenant_id = uuid.uuid4()
        cluster, tracker = await _seed_openshift(services, tenant_id, with_jira=True)
        assert tracker is not None
        async with session_scope(tenant_id) as session:
            await trigger_sync(session, _caller(tenant_id), cluster.id, "scc_assessment_snapshot", mode="full")
        await run_once(queues=("sync", "tickets"), max_jobs=20)

        finding, case = await _open_compliance_case(tenant_id)
        case_id = case.id
        async with session_scope(tenant_id) as session:
            findings = (await session.execute(select(Finding).where(Finding.ocsf_class_uid == 2003))).scalars().all()
            assert len(findings) == 9
            assert sum(row.status == "resolved_by_source" for row in findings) == 8
            assert (await session.execute(select(CorrelationCase))).scalars().all()
            links = (await session.execute(select(TicketLink))).scalars().all()
            assert len(links) == 1 and links[0].case_id == case_id
            tracker_request = await session.get(ActionRequest, links[0].action_request_id)
            assert tracker_request is not None
            await _approve(session, tenant_id, tracker_request)
        await run_once(queues=("actions",), max_jobs=5)
        assert len(state["created"]) == 1

        remediation = await _submit(
            services,
            tenant_id,
            cluster,
            "update_scc",
            {
                "name": "synthetic-restricted",
                "expected_uid": scc["metadata"]["uid"],
                "expected_resource_version": "205",
                "changes": {"allowPrivilegeEscalation": False},
                "approved_plan_hash": APPROVED,
            },
            correlation_id=str(case_id),
        )
        assert _writes(transport, "PATCH", SCC_PATH) == []
        assert (await run_apply_job({"action_request_id": str(remediation.id), "tenant_id": str(tenant_id)})) == {
            "state": "succeeded"
        }
        assert len(_writes(transport, "PATCH", SCC_PATH)) == 1
        assert state["scc"]["allowPrivilegeEscalation"] is False

        async with session_scope(tenant_id) as session:
            persisted_case = await session.get(CorrelationCase, case_id)
            assert persisted_case is not None and persisted_case.detection_state == "open"
            link = (await session.execute(select(TicketLink))).scalar_one()
            assert link.remote_key is not None
            await on_ticket_record(
                session,
                tracker,
                TicketRecord(
                    uid=link.remote_key,
                    key=link.remote_key,
                    status="Done",
                    status_category="done",
                    revision="done-before-source-pass",
                    data={},
                ),
            )
            assert persisted_case.remediation_state == "done"
            assert persisted_case.detection_state == "open"
        await run_once(queues=("sync", "tickets"), max_jobs=10)

        async with session_scope(tenant_id) as session:
            persisted_case = await session.get(CorrelationCase, case_id)
            persisted_finding = await session.get(Finding, finding.id)
            assert persisted_case is not None and persisted_case.detection_state == "resolved_by_source"
            assert persisted_finding is not None and persisted_finding.status == "resolved_by_source"
            assert len((await session.execute(select(TicketLink))).scalars().all()) == 1
            plans = (await session.execute(select(ActionPlanRow))).scalars().all()
            approvals = (await session.execute(select(Approval))).scalars().all()
            assert len(plans) == len(approvals) == 2
            assert {row.plan_hash for row in plans} == {row.plan_hash for row in approvals}
            evidence = (
                await session.execute(select(EvidenceItem).where(EvidenceItem.case_id == case_id))
            ).scalars().all()
            counts = {
                kind: sum(row.kind == kind for row in evidence)
                for kind in ("raw_batch", "action_plan", "approval", "outcome")
            }
            assert counts == {"raw_batch": 2, "action_plan": 2, "approval": 2, "outcome": 2}
            raws = (
                await session.execute(
                    select(RawBatch).where(RawBatch.stream == "scc_assessment_snapshot").order_by(RawBatch.created_at)
                )
            ).scalars().all()
            observations = []
            for raw in raws:
                for record in await _raw_json(services, tenant_id, raw):
                    if record.get("object") is not None:
                        observations.append(record["object"]["allowPrivilegeEscalation"])
            assert observations == [True, False]

            signing_key = Ed25519PrivateKey.generate()
            bundle = await export_evidence_bundle(
                session,
                Caller(id="auditor", tenant_id=tenant_id, roles=frozenset({"auditor"})),
                case_id,
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )
            report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
            assert report["ok"] is True, report
            assert report["evidence_references"]["checked"] == 8
            assert len(bundle["payload"]["policy_decisions"]) == 2
            assert {row["value"] for row in bundle["payload"]["vendor_references"]} == {
                SCC_PATH,
                "ICU-1",
                "jira_issue:ICU-1",
            }

        foreign_id = uuid.uuid4()
        signing_key = Ed25519PrivateKey.generate()
        async with session_scope(foreign_id) as session:
            session.add(Tenant(id=foreign_id, slug=f"t-{foreign_id.hex[:8]}", display_name="Other"))
            await session.flush()
            with pytest.raises(EvidenceExportError):
                await export_evidence_bundle(
                    session,
                    Caller(id="other", tenant_id=foreign_id, roles=frozenset({"auditor"})),
                    case_id,
                    signing_key=signing_key,
                    verification_key=signing_key.public_key(),
                )

    asyncio.run(scenario())


def test_f6_archer_route_fields_and_source_independent_closure(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        scc = _fixture("synthetic_scc_assessment.json")
        scc["allowPrivilegeEscalation"] = True
        state: dict[str, Any] = {"scc": scc, "created": [], "patch_bodies": []}
        transport = RouteTransport({**_scc_routes(state), **_archer_routes(state)})
        services = _services(tmp_path, transport)
        tenant_id = uuid.uuid4()
        cluster, _ = await _seed_openshift(services, tenant_id)
        async with session_scope(tenant_id) as session:
            tracker = await _connection(
                session,
                services,
                tenant_id,
                Archer.kind,
                {
                    "base_url": "https://archer.example.test",
                    "instance_name": "default",
                    "user": "api-user",
                    "password": {"ref": "archer-password"},
                    "record_types": ARCHER_RECORD_TYPES,
                    "write_enabled": True,
                    "destructive_enabled": True,
                },
                {"password": "archer-secret"},
            )
            route = TicketRoute(
                tenant_id=tenant_id,
                name="archer-posture",
                connection_id=tracker.id,
                action="create_finding_or_exception",
                match_json={"ocsf_class_uids": [2003]},
                template_json={
                    "record_type": "findings",
                    "title_field": "Title",
                    "description_field": "Description",
                    "field_values": {},
                },
            )
            session.add(route)
            await session.flush()
            await trigger_sync(session, _caller(tenant_id), cluster.id, "scc_assessment_snapshot", mode="full")
        await run_once(queues=("sync", "tickets"), max_jobs=20)
        _, case = await _open_compliance_case(tenant_id)
        case_id = case.id
        async with session_scope(tenant_id) as session:
            link = (await session.execute(select(TicketLink))).scalar_one()
            request = await session.get(ActionRequest, link.action_request_id)
            assert request is not None
            assert request.args_json["record_type"] == "findings"
            assert request.args_json["correlation_value"] == f"route:{route.id}:case:{case_id}"
            assert set(request.args_json["field_values"]) == {"Title", "Description"}
            assert request.args_json["field_values"]["Title"]
            assert str(case_id) in request.args_json["field_values"]["Description"]
            await _approve(session, tenant_id, request)
        assert await run_once(queues=("actions",), max_jobs=5) == 1
        async with session_scope(tenant_id) as session:
            applied = await session.get(ActionRequest, request.id)
            assert applied is not None and applied.state == "succeeded", (
                applied.state,
                applied.error_class,
                applied.result_json,
            )
        assert len(state["created"]) == 1
        posted = state["created"][0]["Content"]["FieldContents"]
        assert posted["101"]["Value"] == f"route:{route.id}:case:{case_id}"
        assert posted["102"]["Value"]
        assert str(case_id) in posted["104"]["Value"]

        async with session_scope(tenant_id) as session:
            link = (await session.execute(select(TicketLink))).scalar_one()
            assert link.remote_key == "42"
            await on_ticket_record(
                session,
                tracker,
                TicketRecord(
                    uid="42",
                    key="42",
                    status="Done",
                    status_category="done",
                    revision="archer-done-1",
                    data={},
                ),
            )
            persisted = await session.get(CorrelationCase, case_id)
            assert persisted is not None and persisted.remediation_state == "done"
            assert persisted.detection_state == "open"
            state["scc"]["allowPrivilegeEscalation"] = False
            await trigger_sync(session, _caller(tenant_id), cluster.id, "scc_assessment_snapshot", mode="full")
        await run_once(queues=("sync", "tickets"), max_jobs=10)
        async with session_scope(tenant_id) as session:
            persisted = await session.get(CorrelationCase, case_id)
            assert persisted is not None and persisted.detection_state == "resolved_by_source"
            assert len(state["created"]) == 1
            signing_key = Ed25519PrivateKey.generate()
            bundle = await export_evidence_bundle(
                session,
                Caller(id="archer-auditor", tenant_id=tenant_id, roles=frozenset({"auditor"})),
                case_id,
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )
            report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
            assert report["ok"] is True, report
            assert report["evidence_references"]["checked"] == 5

    asyncio.run(scenario())


def test_f6_stale_scc_plan_is_rejected_without_vendor_write(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = {"scc": _fixture("synthetic_scc_assessment.json"), "patch_bodies": []}
        state["scc"]["allowPrivilegeEscalation"] = True
        transport = RouteTransport(_scc_routes(state))
        services = _services(tmp_path, transport)
        tenant_id = uuid.uuid4()
        cluster, _ = await _seed_openshift(services, tenant_id)
        request = await _submit(
            services,
            tenant_id,
            cluster,
            "update_scc",
            {
                "name": "synthetic-restricted",
                "expected_uid": state["scc"]["metadata"]["uid"],
                "expected_resource_version": "205",
                "changes": {"allowPrivilegeEscalation": False},
                "approved_plan_hash": APPROVED,
            },
        )
        state["scc"]["metadata"]["resourceVersion"] = "206"
        payload = {"action_request_id": str(request.id), "tenant_id": str(tenant_id)}
        assert await run_apply_job(payload) == {"state": "stale_plan"}
        assert (await run_apply_job(payload))["skipped"] is True
        assert _writes(transport, "PATCH", SCC_PATH) == []
        async with session_scope(tenant_id) as session:
            stored = await session.get(ActionRequest, request.id)
            plan = await session.get(ActionPlanRow, request.id)
            approval = (await session.execute(select(Approval).where(Approval.action_request_id == request.id))).scalar_one()
            assert stored is not None and stored.state == "stale_plan"
            assert plan is not None and approval.plan_hash == plan.plan_hash

    asyncio.run(scenario())


def _build_routes(state: dict[str, Any]) -> dict[tuple[str, str], Any]:
    def instantiate(_request: Any) -> dict[str, Any]:
        state["instantiate_posts"] += 1
        created_at = datetime.now(UTC).replace(microsecond=0).isoformat()
        state["build"]["metadata"]["creationTimestamp"] = created_at
        for extra in state.get("extra_builds", []):
            extra["metadata"]["creationTimestamp"] = created_at
        state["bc"]["status"]["lastVersion"] = 5
        state["builds"] = [state["build"], *state.get("extra_builds", [])]
        if state.get("timeout"):
            raise httpx2.ReadTimeout("synthetic instantiate response loss")
        return {"status": 201, "json": state["build"]}

    return {
        ("GET", BC_PATH): lambda _request: {"status": 200, "json": state["bc"]},
        ("POST", INSTANTIATE_PATH): instantiate,
        ("GET", BUILDS_PATH): lambda _request: {
            "status": 200,
            "json": {"metadata": {"resourceVersion": "9"}, "items": state["builds"]},
        },
        ("GET", f"{BUILDS_PATH}/web-5"): lambda _request: {"status": 200, "json": state["build"]},
    }


async def _build_request(services: Any, tenant_id: uuid.UUID, cluster: Any) -> ActionRequest:
    return await _submit(
        services,
        tenant_id,
        cluster,
        "instantiate_buildconfig",
        {
            "namespace": "orders",
            "name": "web",
            "expected_uid": "build-config-uid",
            "expected_resource_version": "7",
            "approved_plan_hash": APPROVED,
        },
    )


def _build_state(*, timeout: bool = False) -> dict[str, Any]:
    return {
        "bc": {
            "apiVersion": "build.openshift.io/v1",
            "kind": "BuildConfig",
            "metadata": {
                "name": "web",
                "namespace": "orders",
                "uid": "build-config-uid",
                "resourceVersion": "7",
            },
            "status": {"lastVersion": 4},
        },
        "build": {
            "apiVersion": "build.openshift.io/v1",
            "kind": "Build",
            "metadata": {
                "name": "web-5",
                "namespace": "orders",
                "creationTimestamp": datetime.now(UTC).replace(microsecond=0).isoformat(),
                "labels": {"openshift.io/build-config.name": "web"},
            },
            "status": {"phase": "Running"},
        },
        "builds": [],
        "instantiate_posts": 0,
        "timeout": timeout,
    }


def test_f6_accepted_build_never_repeats_instantiate(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _build_state()
        transport = RouteTransport(_build_routes(state))
        services = _services(tmp_path, transport)
        tenant_id = uuid.uuid4()
        cluster, _ = await _seed_openshift(services, tenant_id)
        request = await _build_request(services, tenant_id, cluster)
        payload = {"action_request_id": str(request.id), "tenant_id": str(tenant_id)}
        assert await run_apply_job(payload) == {"state": "accepted_async"}
        assert (await run_apply_job(payload))["skipped"] is True
        assert (await run_reconcile_job(payload))["state"] == "accepted_async"
        state["build"]["status"]["phase"] = "Complete"
        assert await run_reconcile_job(payload) == {"state": "succeeded"}
        assert state["instantiate_posts"] == 1
        async with session_scope(tenant_id) as session:
            stored = await session.get(ActionRequest, request.id)
            assert stored is not None and stored.state == "succeeded"
            assert stored.result_json is not None
            assert stored.result_json["vendor_ref"] == "web-5"

    asyncio.run(scenario())


def test_f6_timed_out_build_reconciles_window_without_duplicate(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _build_state(timeout=True)
        state["build"]["status"]["phase"] = "Complete"
        transport = RouteTransport(_build_routes(state))
        services = _services(tmp_path, transport)
        tenant_id = uuid.uuid4()
        cluster, _ = await _seed_openshift(services, tenant_id)
        request = await _build_request(services, tenant_id, cluster)
        payload = {"action_request_id": str(request.id), "tenant_id": str(tenant_id)}
        assert await run_apply_job(payload) == {"state": "outcome_unknown"}
        assert await run_reconcile_job(payload) == {"state": "succeeded"}
        assert (await run_apply_job(payload))["skipped"] is True
        assert state["instantiate_posts"] == 1

    asyncio.run(scenario())


def test_f6_ambiguous_build_window_fails_without_second_instantiate(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _build_state(timeout=True)
        state["build"]["status"]["phase"] = "Complete"
        state["extra_builds"] = [
            {
                **state["build"],
                "metadata": {**state["build"]["metadata"], "name": "web-6"},
            }
        ]
        transport = RouteTransport(_build_routes(state))
        services = _services(tmp_path, transport)
        tenant_id = uuid.uuid4()
        cluster, _ = await _seed_openshift(services, tenant_id)
        request = await _build_request(services, tenant_id, cluster)
        payload = {"action_request_id": str(request.id), "tenant_id": str(tenant_id)}
        assert await run_apply_job(payload) == {"state": "outcome_unknown"}
        assert (await run_reconcile_job(payload))["state"] == "failed"
        assert state["instantiate_posts"] == 1
        async with session_scope(tenant_id) as session:
            stored = await session.get(ActionRequest, request.id)
            assert stored is not None and stored.state == "failed"
            assert "ambiguous" in stored.result_json["error"]

    asyncio.run(scenario())


def _route_routes(state: dict[str, Any]) -> dict[tuple[str, str], Any]:
    def listed(_request: Any) -> dict[str, Any]:
        return {
            "status": 200,
            "json": {
                "apiVersion": "route.openshift.io/v1",
                "kind": "RouteList",
                "metadata": {"resourceVersion": state["route"]["metadata"]["resourceVersion"]},
                "items": [state["route"]],
            },
        }

    def patch(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        state["route"]["spec"]["tls"].update(body["spec"]["tls"])
        state["route"]["metadata"]["resourceVersion"] = "205"
        return {"status": 200, "json": state["route"]}

    return {
        ("GET", ROUTE_PATH): lambda _request: {"status": 200, "json": state["route"]},
        ("PATCH", ROUTE_PATH): patch,
        ("GET", "/apis/route.openshift.io/v1/routes"): listed,
    }


def test_f6_route_tls_redacts_raw_and_action_evidence(
    tmp_path: Any, clean_database: None, caplog: pytest.LogCaptureFixture
) -> None:
    async def scenario() -> None:
        route = _fixture("synthetic_route_assessment.json")
        route["status"] = {"ingress": [{"conditions": [{"type": "Admitted", "status": "True"}]}]}
        state = {"route": route}
        transport = RouteTransport(_route_routes(state))
        services = _services(tmp_path, transport)
        tenant_id = uuid.uuid4()
        cluster, _ = await _seed_openshift(services, tenant_id)
        async with session_scope(tenant_id) as session:
            cert_ref = await services.broker.store(tenant_id, "route-cert", b"NEW_ROUTE_CERTIFICATE_PEM", session=session)
            key_ref = await services.broker.store(tenant_id, "route-key", b"NEW_ROUTE_PRIVATE_KEY_PEM", session=session)
            await trigger_sync(session, _caller(tenant_id), cluster.id, "route_assessment_snapshot", mode="full")
        await run_once(queues=("sync", "tickets"), max_jobs=10)
        _, case = await _open_compliance_case(tenant_id)
        case_id = case.id
        request = await _submit(
            services,
            tenant_id,
            cluster,
            "update_route_tls",
            {
                "namespace": "orders",
                "name": "synthetic-checkout",
                "expected_uid": route["metadata"]["uid"],
                "expected_resource_version": "204",
                "termination": "edge",
                "insecure_edge_termination_policy": "Redirect",
                "certificate_ref": cert_ref.model_dump(mode="json"),
                "private_key_ref": key_ref.model_dump(mode="json"),
                "approved_plan_hash": APPROVED,
            },
            correlation_id=str(case_id),
        )
        assert (await run_apply_job({"action_request_id": str(request.id), "tenant_id": str(tenant_id)})) == {
            "state": "succeeded"
        }
        assert len(_writes(transport, "PATCH", ROUTE_PATH)) == 1
        async with session_scope(tenant_id) as session:
            before_refresh = await session.get(CorrelationCase, case_id)
            assert before_refresh is not None and before_refresh.detection_state == "open"
        await run_once(queues=("sync", "tickets"), max_jobs=10)

        async with session_scope(tenant_id) as session:
            after_refresh = await session.get(CorrelationCase, case_id)
            assert after_refresh is not None and after_refresh.detection_state == "resolved_by_source"
            raws = (
                await session.execute(
                    select(RawBatch).where(RawBatch.stream == "route_assessment_snapshot").order_by(RawBatch.created_at)
                )
            ).scalars().all()
            policies = []
            for raw in raws:
                records = await _raw_json(services, tenant_id, raw)
                encoded = json.dumps(records)
                assert "SYNTHETIC_ROUTE_PRIVATE_KEY_VALUE" not in encoded
                assert "NEW_ROUTE_PRIVATE_KEY_PEM" not in encoded
                for record in records:
                    obj = record.get("object")
                    if obj is not None:
                        assert "key" not in obj["spec"]["tls"]
                        policies.append(obj["spec"]["tls"]["insecureEdgeTerminationPolicy"])
            assert policies == ["Allow", "Redirect"]

            surfaces: list[Any] = []
            surfaces.extend(row.ocsf_json for row in (await session.execute(select(Finding))).scalars().all())
            for action in (await session.execute(select(ActionRequest))).scalars().all():
                surfaces.extend((action.args_json, action.result_json))
            for plan in (await session.execute(select(ActionPlanRow))).scalars().all():
                surfaces.extend((plan.diff_json, plan.preconditions_json, plan.request_json))
            surfaces.extend(row.detail_json for row in (await session.execute(select(AuditRecord))).scalars().all())
            signing_key = Ed25519PrivateKey.generate()
            bundle = await export_evidence_bundle(
                session,
                Caller(id="route-auditor", tenant_id=tenant_id, roles=frozenset({"auditor"})),
                case_id,
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )
            surfaces.append(bundle)
            encoded_surfaces = json.dumps(surfaces, default=str)
            assert "SYNTHETIC_ROUTE_PRIVATE_KEY_VALUE" not in encoded_surfaces
            assert "NEW_ROUTE_PRIVATE_KEY_PEM" not in encoded_surfaces
            report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
            assert report["ok"] is True, report
            assert report["evidence_references"]["checked"] == 5
        assert "SYNTHETIC_ROUTE_PRIVATE_KEY_VALUE" not in caplog.text
        assert "NEW_ROUTE_PRIVATE_KEY_PEM" not in caplog.text

    asyncio.run(scenario())


def test_f6_list_watch_relist_snapshot_and_image_digest_identity(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        scc = _fixture("synthetic_scc_assessment.json")
        scc["allowPrivilegeEscalation"] = True
        state: dict[str, Any] = {
            "scc": scc,
            "patch_bodies": [],
            "watch_rvs": [],
            "watch_event": False,
            "expire_watch": False,
        }
        routes = _scc_routes(state)
        collection = "/apis/security.openshift.io/v1/securitycontextconstraints"

        def feed(request: Any) -> dict[str, Any]:
            if request.url.params.get("watch") == "true":
                resource_version = request.url.params["resourceVersion"]
                state["watch_rvs"].append(resource_version)
                if state["expire_watch"]:
                    state["expire_watch"] = False
                    return {"status": 410, "json": {"kind": "Status", "reason": "Expired"}}
                event_type = "MODIFIED" if state["watch_event"] else "BOOKMARK"
                line = {"type": event_type, "object": state["scc"]}
                return {"status": 200, "content": (json.dumps(line) + "\n").encode("utf-8")}
            return {
                "status": 200,
                "json": {
                    "apiVersion": "security.openshift.io/v1",
                    "kind": "SecurityContextConstraintsList",
                    "metadata": {"resourceVersion": state["scc"]["metadata"]["resourceVersion"]},
                    "items": [state["scc"]],
                },
            }

        routes[("GET", collection)] = feed
        transport = RouteTransport(routes)
        services = _services(tmp_path, transport)
        tenant_id = uuid.uuid4()
        cluster, _ = await _seed_openshift(services, tenant_id)

        async def run_stream(name: str, mode: str) -> None:
            async with session_scope(tenant_id) as session:
                await trigger_sync(session, _caller(tenant_id), cluster.id, name, mode=mode)
            assert await run_once(queues=("sync", "tickets"), max_jobs=20) >= 1

        async def checkpoint(name: str) -> str:
            async with session_scope(tenant_id) as session:
                stream_state = (
                    await session.execute(
                        select(StreamState).where(
                            StreamState.connection_id == cluster.id,
                            StreamState.stream == name,
                        )
                    )
                ).scalar_one()
                return stream_state.checkpoint_json["partitions"][
                    "security.openshift.io/v1/securitycontextconstraints@*"
                ]

        await run_stream("scc_assessment_changes", "incremental")
        assert state["watch_rvs"] == []
        assert await checkpoint("scc_assessment_changes") == "205"
        _, case = await _open_compliance_case(tenant_id)
        case_id = case.id

        state["scc"]["allowPrivilegeEscalation"] = False
        state["scc"]["metadata"]["resourceVersion"] = "opaque-watch"
        state["watch_event"] = True
        await run_stream("scc_assessment_changes", "incremental")
        assert state["watch_rvs"] == ["205"]
        assert await checkpoint("scc_assessment_changes") == "opaque-watch"
        async with session_scope(tenant_id) as session:
            assert (await session.get(CorrelationCase, case_id)).detection_state == "resolved_by_source"
            assert len((await session.execute(select(CorrelationCase))).scalars().all()) == 9

        state["watch_event"] = False
        state["expire_watch"] = True
        state["scc"]["allowPrivilegeEscalation"] = True
        state["scc"]["metadata"]["resourceVersion"] = "opaque-relist"
        await run_stream("scc_assessment_changes", "incremental")
        assert state["watch_rvs"][-1] == "opaque-watch"
        assert await checkpoint("scc_assessment_changes") == "opaque-relist"
        async with session_scope(tenant_id) as session:
            assert (await session.get(CorrelationCase, case_id)).detection_state == "open"
            assert len((await session.execute(select(CorrelationCase))).scalars().all()) == 9
        await run_stream("scc_assessment_snapshot", "full")
        async with session_scope(tenant_id) as session:
            assert len((await session.execute(select(CorrelationCase))).scalars().all()) == 9

        image_stream = _fixture("synthetic_openshift_inventory.json")
        image = _fixture("synthetic_image.json")
        state["image_stream"] = image_stream
        state["images"] = [image]
        inventory_paths = {
            "/apis/config.openshift.io/v1/clusterversions": [],
            "/apis/build.openshift.io/v1/buildconfigs": [],
            "/apis/build.openshift.io/v1/builds": [],
            "/apis/image.openshift.io/v1/imagestreams": [image_stream],
            "/apis/image.openshift.io/v1/images": state["images"],
            "/apis/user.openshift.io/v1/users": [],
            "/apis/user.openshift.io/v1/groups": [],
        }
        for path, items in inventory_paths.items():
            routes[("GET", path)] = lambda _request, items=items: {
                "status": 200,
                "json": {
                    "metadata": {"resourceVersion": "inventory-1"},
                    "items": items,
                },
            }
        transport = RouteTransport(routes)
        services = _services(tmp_path, transport)
        await run_stream("openshift_inventory_snapshot", "full")
        async with session_scope(tenant_id) as session:
            records = (
                await session.execute(
                    select(SourceRecordRow).where(SourceRecordRow.record_type == "openshift_inventory")
                )
            ).scalars().all()
            assert len(records) == 2
            image_row = next(row for row in records if row.data_json["kind"] == "Image")
            assert image_row.data_json["digest"] == image_row.data_json["name"]

        new_digest = "sha256:" + "e" * 64
        stable_items = image_stream["status"]["tags"][0]["items"]
        stable_items.insert(
            0,
            {
                "created": "2026-11-10T10:00:00Z",
                "dockerImageReference": f"image-registry.example.invalid/payments/synthetic-api@{new_digest}",
                "image": new_digest,
                "generation": 3,
            },
        )
        image_stream["metadata"]["resourceVersion"] = "206"
        moved_image = {
            **image,
            "metadata": {
                **image["metadata"],
                "name": new_digest,
                "uid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9",
                "resourceVersion": "207",
            },
            "dockerImageReference": f"image-registry.example.invalid/payments/synthetic-api@{new_digest}",
        }
        state["images"].append(moved_image)
        await run_stream("openshift_inventory_snapshot", "full")
        await run_stream("openshift_inventory_snapshot", "full")
        async with session_scope(tenant_id) as session:
            records = (
                await session.execute(
                    select(SourceRecordRow).where(SourceRecordRow.record_type == "openshift_inventory")
                )
            ).scalars().all()
            assert len(records) == 3
            stream_row = next(row for row in records if row.data_json["kind"] == "ImageStream")
            assert [item["image"] for item in stream_row.data_json["tags"]] == [
                new_digest,
                stable_items[1]["image"],
                stable_items[2]["image"],
            ]
            image_rows = [row for row in records if row.data_json["kind"] == "Image"]
            assert {row.data_json["digest"] for row in image_rows} == {image["metadata"]["name"], new_digest}
            assert all(row.data_json["digest"] == row.data_json["name"] for row in image_rows)

    asyncio.run(scenario())

