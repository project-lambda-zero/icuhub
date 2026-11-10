"""F3: Archer exception authority drives separately governed Prisma suppression."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, select

from icuhub.connectors.archer import Archer
from icuhub.connectors.prisma_cloud.models import ReopenAlertInput, SnoozeAlertInput, SuppressionPolicyConfig
from icuhub.core.actions import decide
from icuhub.core.auth_types import Caller
from icuhub.core.correlation import link_finding
from icuhub.core.evidence_export import EvidenceExportError, export_evidence_bundle, verify_evidence_bundle
from icuhub.core.exceptions import run_exception_expiry_job
from icuhub.core.sync import commit_batch
from icuhub.kit.connector import action
from icuhub.kit.errors import StalePlan
from icuhub.kit.testing import RouteTransport, amake_connector
from icuhub.kit.types import ActionOutcome, ActionPlan, ConnectorConfig
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionRequest,
    Approval,
    CaseMember,
    Connection,
    CorrelationCase,
    Finding,
    Job,
    Tenant,
)
from icuhub.workers.main import run_once
from tests.connectors.archer.conftest import BASE_CONFIG, SECRETS
from tests.core.helpers import REGISTRY, caller_for, make_services, new_connection
from tests.core.sample.connector import SampleConfig, SampleScanner

CORRELATION_KEY = "v1|cve|CVE-2026-0001|host:asset-1"


class FlowPrismaConfig(SampleConfig):
    suppression: SuppressionPolicyConfig | None = None


class FlowPrisma(SampleScanner):
    """Prisma-shaped vendor boundary using the production snooze and reopen argument models."""

    kind: ClassVar[str] = "flow_prisma_f3"
    config_model: ClassVar[type[ConnectorConfig]] = FlowPrismaConfig
    capabilities: ClassVar[tuple[str, ...]] = ("FindingSource", "Enforcer")

    @action("snooze_alert", classification="write", capability="Enforcer", input_model=SnoozeAlertInput, idempotency="natural_key")
    async def plan_snooze_alert(self, args: SnoozeAlertInput) -> ActionPlan:
        alert = (await self.http.request("GET", f"/alert/{args.alert_id}")).json()
        expiry = args.dismiss_until.astimezone(UTC).isoformat().replace("+00:00", "Z")
        payload = {"alerts": [args.alert_id], "dismissalExpirationTs": expiry, "note": args.note}
        return ActionPlan(
            action="snooze_alert",
            target_ref=args.alert_id,
            diff={"status": {"from": alert["status"], "to": "snoozed"}},
            preconditions={"status": alert["status"]},
            idempotency_key=f"snooze:{args.alert_id}:{expiry}",
            changed=alert["status"] != "snoozed" or alert.get("dismissalExpirationTs") != expiry,
            request={"path": "/alert/snooze", "payload": payload, "alert_id": args.alert_id},
        )

    @plan_snooze_alert.apply
    async def apply_snooze_alert(self, plan: ActionPlan) -> ActionOutcome:
        alert = (await self.http.request("GET", f"/alert/{plan.request['alert_id']}")).json()
        if alert["status"] != plan.preconditions["status"]:
            raise StalePlan("alert changed after planning")
        response = await self.http.request("POST", plan.request["path"], json=plan.request["payload"], idempotency="non_idempotent")
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=response.json())

    @action("reopen_alert", classification="write", capability="Enforcer", input_model=ReopenAlertInput, idempotency="natural_key")
    async def plan_reopen_alert(self, args: ReopenAlertInput) -> ActionPlan:
        alert = (await self.http.request("GET", f"/alert/{args.alert_id}")).json()
        payload = {"alerts": [args.alert_id], **({"note": args.note} if args.note else {})}
        return ActionPlan(
            action="reopen_alert",
            target_ref=args.alert_id,
            diff={"status": {"from": alert["status"], "to": "open"}},
            preconditions={"status": alert["status"]},
            idempotency_key=f"reopen:{args.alert_id}:{alert['status']}",
            changed=alert["status"] != "open",
            request={"path": "/alert/reopen", "payload": payload, "alert_id": args.alert_id},
        )

    @plan_reopen_alert.apply
    async def apply_reopen_alert(self, plan: ActionPlan) -> ActionOutcome:
        alert = (await self.http.request("GET", f"/alert/{plan.request['alert_id']}")).json()
        if alert["status"] != plan.preconditions["status"]:
            raise StalePlan("alert changed after planning")
        response = await self.http.request("POST", plan.request["path"], json=plan.request["payload"], idempotency="non_idempotent")
        return ActionOutcome(status="succeeded", vendor_ref=plan.target_ref, result=response.json())


def _transport(state: dict[str, Any]) -> RouteTransport:
    def read_alert(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": dict(state["alert"])}

    def snooze(request: Any) -> dict[str, Any]:
        state["snooze_writes"] += 1
        state["alert"]["status"] = "snoozed"
        import json  # noqa: PLC0415

        state["alert"]["dismissalExpirationTs"] = json.loads(request.content)["dismissalExpirationTs"]
        return {"status": 200, "json": dict(state["alert"])}

    def reopen(_request: Any) -> dict[str, Any]:
        state["reopen_writes"] += 1
        state["alert"]["status"] = "open"
        state["alert"]["dismissalExpirationTs"] = None
        return {"status": 200, "json": dict(state["alert"])}

    return RouteTransport(
        {
            ("GET", "/api/ping"): {"status": 200, "json": {"ok": True}},
            ("GET", "/api/findings"): {"status": 200, "json": {"items": []}},
            ("GET", "/alert/alert-1"): read_alert,
            ("POST", "/alert/snooze"): snooze,
            ("POST", "/alert/reopen"): reopen,
        }
    )


def _policy(expiry_placeholder: str = "{exception_expires_at}") -> dict[str, Any]:
    return {
        "action": "snooze_alert",
        "args": {
            "alert_id": "{source_uid}",
            "dismiss_until": expiry_placeholder,
            "note": "Archer exception {exception_revision}",
        },
        "reversal_action": "reopen_alert",
        "reversal_args": {"alert_id": "{source_uid}", "note": "Exception ended"},
    }


def _record_types() -> dict[str, Any]:
    return {
        "exception_requests": {
            "application_id": 301,
            "level_id": 401,
            "correlation_field": "Hub Case",
            "decision_field": "Review Decision",
            "revision_field": "Review Revision",
            "expiry_field": "Review Expiry",
            "scope_field": "Scoped Alerts",
        }
    }


def _decision(status: str, revision: str, expires_at: datetime | None) -> dict[str, Any]:
    return {
        "content_id": 2001,
        "level_id": 401,
        "application_id": 301,
        "record_type": "exception_requests",
        "fields": {
            "Hub Case": CORRELATION_KEY,
            "Review Decision": status,
            "Review Revision": revision,
            "Review Expiry": expires_at.isoformat() if expires_at else None,
            "Scoped Alerts": ["alert-1"] if status == "approved" else [],
        },
    }


async def _seed(
    services: Any,
    tenant_id: uuid.UUID,
    state: dict[str, Any],
) -> dict[str, Any]:
    async with session_scope(tenant_id) as session:
        session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
        await session.flush()
        source = await new_connection(
            session,
            services,
            tenant_id,
            kind=FlowPrisma.kind,
            config={
                "base_url": "http://127.0.0.1:9",
                "allow_plain_http_loopback": True,
                "suppression": _policy(),
            },
        )
        archer_connection = await new_connection(
            session,
            services,
            tenant_id,
            kind="archer",
            config={
                "base_url": "https://archer.example.test",
                "instance_name": "default",
                "user": "api-user",
                "record_types": _record_types(),
            },
            secrets={"password": "test-password"},
        )
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
                "resources": [{"hostname": "asset-1"}],
                "vulnerabilities": [{"cve": {"uid": "CVE-2026-0001"}}],
            },
            revision_digest="alert-revision-1",
            mapper_version=1,
            correlation_key=CORRELATION_KEY,
        )
        session.add(finding)
        await session.flush()
        case = await link_finding(session, finding)
        return {
            "source_id": source.id,
            "archer_connection_id": archer_connection.id,
            "finding_id": finding.id,
            "case_id": case.id,
        }


async def _ingest(tenant_id: uuid.UUID, ids: dict[str, Any], raw: dict[str, Any]) -> None:
    async with session_scope(tenant_id) as session:
        connection = await session.get(Connection, ids["archer_connection_id"])
        assert connection is not None
        connector = await amake_connector(
            Archer,
            {**BASE_CONFIG, "record_types": _record_types()},
            RouteTransport({}),
            SECRETS,
        )
        await commit_batch(
            session,
            connection=connection,
            connector=connector,
            stream="exception_requests",
            records=[raw],
            origin="stream",
        )


async def _approve_pending(tenant_id: uuid.UUID) -> None:
    async with session_scope(tenant_id) as session:
        requests = list((await session.scalars(select(ActionRequest).where(ActionRequest.state == "pending_approval"))).all())
        for request in requests:
            approval = (await session.scalars(select(Approval).where(Approval.action_request_id == request.id))).one()
            await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")


async def _expire(tenant_id: uuid.UUID, case_id: uuid.UUID, expiry: datetime, monkeypatch: pytest.MonkeyPatch) -> None:
    class AfterExpiry(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN001, D102
            value = expiry + timedelta(seconds=1)
            return value if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr("icuhub.core.exceptions.datetime", AfterExpiry)
    result = await run_exception_expiry_job(
        {"tenant_id": str(tenant_id), "case_id": str(case_id), "scheduled_for": expiry.isoformat()}
    )
    assert result == {"expired": 1}


def test_f3_approval_expiry_reversal_and_f7_evidence(tmp_path: Any, clean_database: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(REGISTRY, FlowPrisma.kind, FlowPrisma)
    monkeypatch.setitem(REGISTRY, "archer", Archer)

    async def scenario() -> None:
        state = {"alert": {"status": "open", "dismissalExpirationTs": None}, "snooze_writes": 0, "reopen_writes": 0}
        services = make_services(_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        ids = await _seed(services, tenant_id, state)
        expiry = datetime.now(UTC) + timedelta(hours=1)
        await _ingest(tenant_id, ids, _decision("approved", "archer-revision-7", expiry))
        async with session_scope(tenant_id) as session:
            case = await session.get(CorrelationCase, ids["case_id"])
            assert case is not None and case.exception_state == "approved"
            assert case.exception_revision == "archer-revision-7"
            assert case.exception_scope_uids == ["alert-1"]
            request = (await session.scalars(select(ActionRequest))).one()
            assert request.action == "snooze_alert" and request.state == "pending_approval"
            assert request.args_json["dismiss_until"] == expiry.isoformat()
            assert state["snooze_writes"] == 0
        await _approve_pending(tenant_id)
        assert await run_once(queues=("actions",), max_jobs=5) == 1
        assert state["alert"]["status"] == "snoozed"
        assert state["snooze_writes"] == 1

        expiry = expiry + timedelta(hours=1)
        await _ingest(tenant_id, ids, _decision("approved", "archer-revision-8", expiry))
        async with session_scope(tenant_id) as session:
            case = await session.get(CorrelationCase, ids["case_id"])
            assert case is not None and case.exception_revision == "archer-revision-8"
            assert len(list((await session.scalars(select(ActionRequest).where(ActionRequest.action == "snooze_alert"))).all())) == 1
            reversal = (await session.scalars(select(ActionRequest).where(ActionRequest.action == "reopen_alert"))).one()
            assert reversal.state == "pending_approval"
        await _approve_pending(tenant_id)
        assert await run_once(queues=("actions",), max_jobs=5) == 1
        assert state["alert"]["status"] == "open"
        async with session_scope(tenant_id) as session:
            suppressions = list((await session.scalars(select(ActionRequest).where(ActionRequest.action == "snooze_alert"))).all())
            assert len(suppressions) == 2
            assert {request.state for request in suppressions} == {"succeeded", "pending_approval"}
        await _approve_pending(tenant_id)
        assert await run_once(queues=("actions",), max_jobs=5) == 1
        assert state["alert"]["status"] == "snoozed"
        assert state["alert"]["dismissalExpirationTs"] == expiry.isoformat().replace("+00:00", "Z")

        await _expire(tenant_id, ids["case_id"], expiry, monkeypatch)
        async with session_scope(tenant_id) as session:
            case = await session.get(CorrelationCase, ids["case_id"])
            assert case is not None and case.exception_state == "expired"
            reversal = (
                await session.scalars(
                    select(ActionRequest).where(
                        ActionRequest.action == "reopen_alert",
                        ActionRequest.state == "pending_approval",
                    )
                )
            ).one()
        await _approve_pending(tenant_id)
        assert await run_once(queues=("actions", "sync"), max_jobs=10) >= 2
        assert state["alert"]["status"] == "open"
        assert state["snooze_writes"] == 2
        assert state["reopen_writes"] == 2

        signing_key = Ed25519PrivateKey.generate()
        async with session_scope(tenant_id) as session:
            bundle = await export_evidence_bundle(
                session,
                Caller(id="auditor-f3", tenant_id=tenant_id, roles=frozenset({"auditor"})),
                ids["case_id"],
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )
        report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
        assert report["ok"] is True, report
        payload = bundle["payload"]
        assert payload["correlation_case"]["exception_state"] == "expired"
        assert payload["correlation_case"]["exception_revision"] == "archer-revision-8"
        assert payload["correlation_case"]["exception_scope_uids"] == ["alert-1"]
        assert {row["action"] for row in payload["actions"]} == {"snooze_alert", "reopen_alert"}
        assert len(payload["plans"]) == 4 and len(payload["approvals"]) == 4
        assert payload["raw_batches"] and payload["evidence"]
        evidence_counts = {
            kind: sum(row["kind"] == kind for row in payload["evidence"])
            for kind in ("raw_batch", "action_plan", "approval", "outcome")
        }
        assert evidence_counts == {"raw_batch": 2, "action_plan": 4, "approval": 4, "outcome": 4}
        assert report["evidence_references"]["checked"] == 14
        assert len(payload["evidence"]) == 14
        assert {row["value"] for row in payload["vendor_references"]} == {"alert-1"}

        foreign_id = uuid.uuid4()
        async with session_scope(foreign_id) as session:
            session.add(Tenant(id=foreign_id, slug=f"t-{foreign_id.hex[:8]}", display_name="Other"))
            await session.flush()
            with pytest.raises(EvidenceExportError):
                await export_evidence_bundle(
                    session,
                    Caller(id="foreign-auditor", tenant_id=foreign_id, roles=frozenset({"auditor"})),
                    ids["case_id"],
                    signing_key=signing_key,
                    verification_key=signing_key.public_key(),
                )

    asyncio.run(scenario())


def test_f3_rejection_performs_no_suppression(tmp_path: Any, clean_database: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(REGISTRY, FlowPrisma.kind, FlowPrisma)
    monkeypatch.setitem(REGISTRY, "archer", Archer)

    async def scenario() -> None:
        state = {"alert": {"status": "open"}, "snooze_writes": 0, "reopen_writes": 0}
        services = make_services(_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        ids = await _seed(services, tenant_id, state)
        await _ingest(tenant_id, ids, _decision("rejected", "archer-revision-8", None))
        async with session_scope(tenant_id) as session:
            case = await session.get(CorrelationCase, ids["case_id"])
            assert case is not None and case.exception_state == "rejected"
            assert list((await session.scalars(select(ActionRequest))).all()) == []
            finding = await session.get(Finding, ids["finding_id"])
            assert finding is not None and finding.status == "open"
        assert state["snooze_writes"] == 0

    asyncio.run(scenario())


def test_f3_late_suppression_after_expiry_is_reversed_even_after_member_removal(
    tmp_path: Any, clean_database: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(REGISTRY, FlowPrisma.kind, FlowPrisma)
    monkeypatch.setitem(REGISTRY, "archer", Archer)

    async def scenario() -> None:
        state = {"alert": {"status": "open"}, "snooze_writes": 0, "reopen_writes": 0}
        services = make_services(_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        ids = await _seed(services, tenant_id, state)
        expiry = datetime.now(UTC) + timedelta(hours=1)
        await _ingest(tenant_id, ids, _decision("approved", "archer-revision-9", expiry))
        await _approve_pending(tenant_id)
        await _expire(tenant_id, ids["case_id"], expiry, monkeypatch)
        async with session_scope(tenant_id) as session:
            await session.execute(delete(CaseMember).where(CaseMember.finding_id == ids["finding_id"]))
        assert await run_once(queues=("actions",), max_jobs=5) == 1
        assert state["alert"]["status"] == "snoozed"
        async with session_scope(tenant_id) as session:
            reversal = (await session.scalars(select(ActionRequest).where(ActionRequest.action == "reopen_alert"))).one()
            assert reversal.state == "pending_approval"
        await _approve_pending(tenant_id)
        assert await run_once(queues=("actions", "sync"), max_jobs=10) >= 2
        assert state["alert"]["status"] == "open"
        assert state["snooze_writes"] == 1 and state["reopen_writes"] == 1

    asyncio.run(scenario())


def test_f3_expiry_job_rearms_early_and_ignores_stale_schedule(
    tmp_path: Any, clean_database: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(REGISTRY, FlowPrisma.kind, FlowPrisma)
    monkeypatch.setitem(REGISTRY, "archer", Archer)

    async def scenario() -> None:
        state = {"alert": {"status": "open"}, "snooze_writes": 0, "reopen_writes": 0}
        services = make_services(_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        ids = await _seed(services, tenant_id, state)
        expiry = datetime.now(UTC) + timedelta(hours=2)
        await _ingest(tenant_id, ids, _decision("approved", "archer-revision-10", expiry))

        class BeforeExpiry(datetime):
            @classmethod
            def now(cls, tz=None):  # noqa: ANN001, D102
                value = expiry - timedelta(hours=1)
                return value if tz is not None else value.replace(tzinfo=None)

        monkeypatch.setattr("icuhub.core.exceptions.datetime", BeforeExpiry)
        payload = {"tenant_id": str(tenant_id), "case_id": str(ids["case_id"]), "scheduled_for": expiry.isoformat()}
        assert await run_exception_expiry_job(payload) == {"expired": 0}
        async with session_scope(tenant_id) as session:
            case = await session.get(CorrelationCase, ids["case_id"])
            assert case is not None and case.exception_state == "approved"
            jobs = list((await session.scalars(select(Job).where(Job.kind == "exception_expiry"))).all())
            assert len(jobs) == 2
            assert {job.payload_json["scheduled_for"] for job in jobs} == {expiry.isoformat()}

        replacement_expiry = expiry + timedelta(hours=1)
        await _ingest(tenant_id, ids, _decision("approved", "archer-revision-11", replacement_expiry))
        assert await run_exception_expiry_job(payload) == {"expired": 0}
        async with session_scope(tenant_id) as session:
            case = await session.get(CorrelationCase, ids["case_id"])
            assert case is not None and case.exception_state == "approved"
            assert case.exception_revision == "archer-revision-11"
            assert case.exception_expires_at == replacement_expiry
        assert state["snooze_writes"] == 0 and state["reopen_writes"] == 0

    asyncio.run(scenario())
