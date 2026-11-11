"""Flow F1 over production connectors: scanner -> correlation -> Jira Cloud -> status sync.

Unlike ``test_flow_f1.py``, which uses sample doubles, these oracles resolve kinds from the real
``CONNECTORS`` registry and drive the real connector classes. Vendor I/O is answered by
``RouteTransport`` from the synthetic fixtures under ``tests/fixtures``; Postgres is real.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from icuhub.connectors import CONNECTORS
from icuhub.connectors.fortify_fod import FortifyFod
from icuhub.connectors.fortify_ssc import FortifySsc
from icuhub.connectors.invicti_enterprise import InvictiEnterprise
from icuhub.connectors.invicti_standard import InvictiStandard
from icuhub.connectors.jira_cloud.connector import JiraCloud
from icuhub.connectors.mend_sca import MendSca
from icuhub.connectors.nessus import Nessus
from icuhub.core.actions import decide, run_apply_job, run_reconcile_job
from icuhub.core.audit import verify_chain
from icuhub.core.auth_types import Caller
from icuhub.core.connections import create_connection
from icuhub.core.evidence_export import export_evidence_bundle, verify_evidence_bundle
from icuhub.core.services import configure
from icuhub.core.sync import run_sync_job, submit_import, trigger_sync
from icuhub.core.tickets import on_ticket_record
from icuhub.kit.testing import RouteTransport
from icuhub.kit.types import TicketRecord
from icuhub.settings import Settings
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionRequest,
    Approval,
    CorrelationCase,
    Finding,
    Job,
    SyncRun,
    Tenant,
    TicketLink,
    TicketRoute,
)
from icuhub.storage.models import Target as TargetRow
from icuhub.workers.main import run_once

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
INVICTI_BASE = "https://invicti.example.test/api/1.0"
NESSUS_BASE = "https://nessus.example.test"
JIRA_BASE = "https://jira.example.test"
INVICTI_TOKEN_REF = "invicti-api-token"
NESSUS_ACCESS_REF = "nessus-access-key"
NESSUS_SECRET_REF = "nessus-secret-key"
JIRA_TOKEN_REF = "jira-api-token"
JIRA_ACCOUNT = "svc-automation@example.test"
JIRA_KEY = "ICU"
SSC_BASE = "https://ssc.example.test/ssc"
FOD_BASE = "https://api.ams.fortify.com"
MEND_BASE = "https://mend.example.test"
MEND_ORG = "00000000-0000-4000-8000-000000000002"
MEND_PROJECT = "00000000-0000-4000-8000-000000000101"


@dataclass(frozen=True)
class _Scanner:
    """A production scanner connection plus the recorded vendor routes it talks to."""

    kind: str
    config: dict[str, Any]
    secrets: dict[str, str]
    routes: dict[tuple[str, str], Any]
    stream: str
    mode: str
    min_severity_id: int
    min_cases: int = 1
    target: tuple[str, str, str] | None = None
    route_own: bool = False
    importer: str | None = None
    import_filename: str = "report.json"
    import_data: bytes = b""
    uncertain_create: bool = False
    control: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _F1Result:
    scanner: _Scanner
    services: Any
    tenant_id: uuid.UUID
    source_id: uuid.UUID
    tracker_id: uuid.UUID
    target_id: uuid.UUID | None
    case_id: uuid.UUID
    state: dict[str, Any]


def _fixture(*parts: str) -> Any:
    return json.loads((FIXTURES.joinpath(*parts)).read_text(encoding="utf-8"))


def _jira_routes(state: dict[str, Any]) -> dict[tuple[str, str], Any]:
    """Recorded Jira Cloud answers. ``state["created"]`` records every issue the connector creates."""

    def jira_create(request: Any) -> dict[str, Any]:
        body = json.loads(request.content)
        key = f"{JIRA_KEY}-{len(state['created']) + 1}"
        state["created"].append({"id": str(10000 + len(state["created"])), "key": key, "body": body})
        if state.get("create_timeout"):
            raise httpx2.ReadTimeout("synthetic Jira timeout after issue creation")
        return {"status": 201, "json": {"id": state["created"][-1]["id"], "key": key}}

    def jira_search(_request: Any) -> dict[str, Any]:
        issues = state["created"] if state.get("index_visible") else []
        return {"status": 200, "json": {"issues": issues, "isLast": True}}

    def jira_issue(_request: Any) -> dict[str, Any]:
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
        ("GET", "/rest/api/3/search/jql"): jira_search,
        ("GET", "/rest/api/3/issue/ICU-1"): jira_issue,
        ("POST", "/rest/api/3/issue"): jira_create,
    }


def _invicti_scanner() -> _Scanner:
    issues = _fixture("invicti_enterprise", "issues.json")
    issues["List"][0]["Classification"]["Cve"] = "CVE-2026-1234"
    scans = _fixture("invicti_enterprise", "scans.json")
    return _Scanner(
        kind=InvictiEnterprise.kind,
        config={"base_url": INVICTI_BASE, "user_id": "api-user", "api_token": {"ref": INVICTI_TOKEN_REF}},
        secrets={"api_token": "synthetic-invicti-token"},
        routes={
            ("GET", "/api/1.0/issues/allissues"): {"status": 200, "json": issues},
            ("GET", "/api/1.0/scans/list"): {"status": 200, "json": scans},
            ("GET", "/api/1.0/scans/listbystatechanged"): {"status": 200, "json": scans},
        },
        stream="issues",
        mode="incremental",
        min_severity_id=4,
    )


def _nessus_scanner() -> _Scanner:
    report = (FIXTURES / "nessus" / "sample_scan.nessus").read_text(encoding="utf-8")
    scans = {"scans": [{"id": 1, "name": "weekly", "uuid": "u-1", "status": "completed"}], "folders": []}
    return _Scanner(
        kind=Nessus.kind,
        config={
            "base_url": NESSUS_BASE,
            "auth_mode": "api_keys",
            "access_key": {"ref": NESSUS_ACCESS_REF},
            "secret_key": {"ref": NESSUS_SECRET_REF},
        },
        secrets={"access_key": "synthetic-nessus-access", "secret_key": "synthetic-nessus-secret"},
        routes={
            ("GET", "/scans"): {"status": 200, "json": scans},
            ("POST", "/scans/1/export"): {"status": 200, "json": {"file": 77}},
            ("GET", "/scans/1/export/77/status"): {"status": 200, "json": {"status": "ready"}},
            ("GET", "/scans/1/export/77/download"): {"status": 200, "text": report},
        },
        stream="export_findings",
        mode="full",
        min_severity_id=5,
        min_cases=2,
    )


def _fortify_ssc_scanner() -> _Scanner:
    page = _fixture("fortify_ssc", "issues_page1.json")
    page["data"] = page["data"][:1]
    page["count"] = 1
    return _Scanner(
        kind=FortifySsc.kind,
        config={"base_url": SSC_BASE, "api_token": {"ref": "fortify-token"}},
        secrets={"api_token": "synthetic-fortify-token"},
        routes={("GET", "/ssc/api/v1/projectVersions/42/issues"): {"status": 200, "json": page}},
        stream="issues",
        mode="full",
        min_severity_id=0,
        target=("42", "project_version", "synthetic-app"),
        route_own=True,
    )


def _fortify_fod_scanner() -> _Scanner:
    vulnerability = {
        "id": 1,
        "vulnId": "vuln-1",
        "instanceId": "instance-1",
        "severity": 4,
        "severityString": "High",
        "lastModifiedDate": "2026-11-09",
        "developerStatus": "New",
        "auditorStatus": "Unreviewed",
        "category": "SQL Injection",
        "cwe": "89",
        "primaryLocation": "src/app/Db.java",
        "lineNumber": 88,
    }
    return _Scanner(
        kind=FortifyFod.kind,
        config={"base_url": FOD_BASE, "client_id": "client-1", "client_secret": {"ref": "fod-secret"}},
        secrets={"client_secret": "synthetic-fod-secret"},
        routes={
            ("POST", "/oauth/token"): {"status": 200, "json": {"access_token": "token-1", "expires_in": 3600}},
            ("GET", "/api/v3/releases/42/vulnerabilities"): {
                "status": 200,
                "json": {"items": [vulnerability], "offset": 0, "limit": 50, "totalCount": 1},
            },
        },
        stream="issues",
        mode="full",
        min_severity_id=4,
        target=("42", "release", "Release 42"),
    )


def _mend_scanner() -> _Scanner:
    control: dict[str, Any] = {"partial": False}
    first = _fixture("mend_sca", "v3", "security_findings_page1.json")
    first["response"] = first["response"][:1]
    first["additionalData"]["totalItems"] = 2
    second = _fixture("mend_sca", "v3", "security_findings_page2.json")

    def findings(request: Any) -> dict[str, Any]:
        cursor = request.url.params.get("cursor")
        if control["partial"]:
            if cursor is None:
                return {
                    "status": 200,
                    "json": {
                        "additionalData": {"totalItems": 2, "next": "partial-page-2"},
                        "response": [first["response"][0]],
                    },
                }
            return {"status": 500, "json": {"error": "synthetic partial page failure"}}
        if cursor is None:
            return {"status": 200, "json": first}
        overlap = [first["response"][0], *second["response"]]
        return {
            "status": 200,
            "json": {"additionalData": {"totalItems": 3, "next": None, "cursor": None}, "response": overlap},
        }

    return _Scanner(
        kind=MendSca.kind,
        config={
            "base_url": MEND_BASE,
            "api_version": "3.0",
            "email": "api-user@example.test",
            "user_key": {"ref": "mend-user-key"},
            "org_uuid": MEND_ORG,
        },
        secrets={"user_key": "synthetic-mend-user-key"},
        routes={
            # Login returns the refresh token (https://api-docs.mend.io/platform/3.0/access-management/login.md);
            # the JWT comes from the access-token exchange (.../refreshaccesstoken.md).
            ("POST", "/api/v3.0/login"): {
                "status": 200,
                "json": {"response": {"userUuid": MEND_ORG, "refreshToken": "refresh", "jwtTTL": 1800}},
            },
            ("POST", "/api/v3.0/login/accessToken"): {
                "status": 200,
                "json": {"response": {"orgUuid": MEND_ORG, "jwtToken": "jwt", "tokenTTL": 1800}},
            },
            ("GET", f"/api/v3.0/projects/{MEND_PROJECT}/dependencies/findings/security"): findings,
        },
        stream="security_findings",
        mode="full",
        min_severity_id=4,
        min_cases=2,
        target=(MEND_PROJECT, "project", "example-project-one"),
        control=control,
    )


def _invicti_standard_scanner() -> _Scanner:
    data = (FIXTURES / "invicti_standard" / "report.json").read_bytes()
    return _Scanner(
        kind=InvictiStandard.kind,
        config={
            "base_url": "",
            "report_files": [],
            "website_id": "website-configured-1",
            "website_name": "Blog",
            "webhook_mode": "static_header",
        },
        secrets={},
        routes={},
        stream="report_issues",
        mode="full",
        min_severity_id=3,
        importer="invicti_json",
        import_data=data,
    )


def _caller(tenant_id: uuid.UUID, name: str = "admin", roles: set[str] | None = None) -> Caller:
    return Caller(
        id=name,
        tenant_id=tenant_id,
        roles=frozenset(roles or {"admin"}),
        groups=frozenset({"secops"}),
    )


def _services(tmp_path: Path, transport: RouteTransport) -> Any:
    kek_path = tmp_path / "kek"
    kek_path.write_bytes(bytes(range(32)))
    settings = Settings(
        database_url=_database_url(),
        kek_provider="file",
        kek_file_path=kek_path,
        automation_enabled=False,
    )
    return configure(settings, registry=CONNECTORS, transport=transport)


def _database_url() -> str:
    return os.environ["ICUHUB_DATABASE_URL"]


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
        slug=f"{kind}-{uuid.uuid4().hex[:6]}",
        display_name=kind,
        config=config,
        secrets=secrets,
        caller=_caller(tenant_id),
        registry=CONNECTORS,
        broker=services.broker,
    )


async def _run_f1(tmp_path: Path, scanner: _Scanner) -> _F1Result:
    state: dict[str, Any] = {
        "created": [],
        "create_timeout": scanner.uncertain_create,
        "index_visible": False,
    }
    services = _services(tmp_path, RouteTransport({**scanner.routes, **_jira_routes(state)}))
    tenant_id = uuid.uuid4()
    target_id: uuid.UUID | None = None
    async with session_scope(tenant_id) as session:
        session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
        await session.flush()
        source = await _connection(session, services, tenant_id, scanner.kind, scanner.config, scanner.secrets)
        tracker = await _connection(
            session,
            services,
            tenant_id,
            JiraCloud.kind,
            {
                "base_url": JIRA_BASE,
                "auth_method": "basic",
                "account_email": JIRA_ACCOUNT,
                "api_token": {"ref": JIRA_TOKEN_REF},
                "jql": f"project = {JIRA_KEY}",
            },
            {"api_token": "synthetic-jira-token"},
        )
        if scanner.target is not None:
            source_uid, target_kind, display_name = scanner.target
            target = TargetRow(
                tenant_id=tenant_id,
                connection_id=source.id,
                source_uid=source_uid,
                kind=target_kind,
                display_name=display_name,
                attributes_json={},
            )
            session.add(target)
            await session.flush()
            target_id = target.id
        session.add(
            TicketRoute(
                tenant_id=tenant_id,
                name="high",
                connection_id=tracker.id,
                action="create_issue",
                match_json={
                    "min_severity_id": scanner.min_severity_id,
                    "require_correlation_key": not scanner.route_own,
                },
                template_json={"project_key": JIRA_KEY, "issue_type": "Bug", "labels": ["security"]},
            )
        )
        await session.flush()
        if scanner.importer is None:
            await trigger_sync(
                session, _caller(tenant_id), source.id, scanner.stream, target_id=target_id, mode=scanner.mode
            )
        else:
            await submit_import(
                session,
                _caller(tenant_id),
                source.id,
                scanner.importer,
                scanner.import_filename,
                scanner.import_data,
            )
    assert await run_once(queues=("sync", "imports", "tickets"), max_jobs=10) >= 2
    async with session_scope(tenant_id) as session:
        cases = (await session.execute(select(CorrelationCase))).scalars().all()
        assert len(cases) >= scanner.min_cases
        routed_cases = [
            item
            for item in cases
            if (scanner.route_own or not item.correlation_key.startswith("v1|own|"))
            and item.severity_id >= scanner.min_severity_id
        ]
        assert len(routed_cases) == 1, (
            scanner.min_severity_id,
            [(item.correlation_key, item.severity_id) for item in routed_cases],
            [(item.correlation_key, item.severity_id) for item in cases],
        )
        case = routed_cases[0]
        case_id = case.id
        members = (await session.execute(select(Finding))).scalars().all()
        assert members, f"{scanner.kind} must produce findings"
        requests = (await session.execute(select(ActionRequest))).scalars().all()
        assert len(requests) == 1, (
            case.correlation_key,
            case.severity_id,
            case.remediation_state,
            [(link.state, link.remote_key) for link in (await session.execute(select(TicketLink))).scalars().all()],
        )
        request = requests[0]
        approval = (await session.execute(select(Approval))).scalar_one()
        await decide(session, _caller(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
        assert request.state == "approved"
        apply_job = (
            await session.execute(select(Job).where(Job.kind == "apply", Job.state == "queued"))
        ).scalars().one()
        apply_payload = dict(apply_job.payload_json)
        assert apply_payload["tenant_id"] == str(tenant_id)
    if scanner.uncertain_create:
        applied = await run_apply_job(apply_payload)
        assert applied["state"] == "outcome_unknown", applied
        assert len(state["created"]) == 1
        state["index_visible"] = True
        reconciled = await run_reconcile_job(apply_payload)
        assert reconciled["state"] == "succeeded", reconciled
    else:
        assert await run_once(queues=("actions",), max_jobs=5) == 1
    assert len(state["created"]) == 1, "exactly one Jira create for one routed case"
    created = state["created"][0]
    assert created["body"]["fields"]["project"]["key"] == JIRA_KEY

    async with session_scope(tenant_id) as session:
        if scanner.importer is None:
            await trigger_sync(
                session, _caller(tenant_id), source.id, scanner.stream, target_id=target_id, mode=scanner.mode
            )
        else:
            await submit_import(
                session,
                _caller(tenant_id),
                source.id,
                scanner.importer,
                scanner.import_filename,
                scanner.import_data,
            )
    await run_once(queues=("sync", "imports", "tickets"), max_jobs=10)
    assert len(state["created"]) == 1, "replay must not create a second Jira issue"

    signing_key = Ed25519PrivateKey.generate()
    verification_key = signing_key.public_key()
    async with session_scope(tenant_id) as session:
        assert len((await session.execute(select(ActionRequest))).scalars().all()) == 1
        link = (await session.execute(select(TicketLink))).scalars().one()
        assert link.remote_key == created["key"]
        assert link.state == "succeeded"
        await on_ticket_record(
            session,
            tracker,
            TicketRecord(
                uid=created["key"],
                key=created["key"],
                status="Done",
                status_category="done",
                revision="inbound-1",
                data={},
            ),
        )
        case = await session.get(CorrelationCase, case_id)
        assert case is not None and case.remediation_state == "done"
        await on_ticket_record(
            session,
            tracker,
            TicketRecord(
                uid=created["key"],
                key=created["key"],
                status="In Progress",
                status_category="in_progress",
                revision="inbound-2",
                data={},
            ),
        )
        case = await session.get(CorrelationCase, case_id)
        assert case is not None and case.remediation_state == "in_progress"
        for row in (await session.execute(select(Finding))).scalars().all():
            assert row.status != "resolved_by_source"
        verdict = await verify_chain(session, tenant_id)
        assert verdict.ok and verdict.checked > 0
        bundle = await export_evidence_bundle(
            session,
            _caller(tenant_id, "auditor-f1", roles={"auditor"}),
            case_id,
            signing_key=signing_key,
            verification_key=verification_key,
        )
    report = verify_evidence_bundle(bundle, verification_key=verification_key)
    assert report["ok"] is True, report
    payload = bundle["payload"]
    assert payload["correlation_case"]["id"] == str(case_id)
    assert payload["raw_batches"] and payload["ticket_links"]
    assert len(payload["actions"]) == len(payload["plans"]) == len(payload["approvals"]) == 1
    return _F1Result(scanner, services, tenant_id, source.id, tracker.id, target_id, case_id, state)


def test_f1_invicti_enterprise_to_jira_cloud_real_connectors(tmp_path: Path, clean_database: None) -> None:
    asyncio.run(_run_f1(tmp_path, _invicti_scanner()))


def test_f1_nessus_to_jira_cloud_real_connectors(tmp_path: Path, clean_database: None) -> None:
    asyncio.run(_run_f1(tmp_path, _nessus_scanner()))


def test_f1_fortify_ssc_to_jira_cloud_real_connectors(tmp_path: Path, clean_database: None) -> None:
    asyncio.run(_run_f1(tmp_path, _fortify_ssc_scanner()))


def test_f1_fortify_fod_to_jira_cloud_real_connectors(tmp_path: Path, clean_database: None) -> None:
    asyncio.run(_run_f1(tmp_path, _fortify_fod_scanner()))


def test_f1_mend_overlap_to_jira_cloud_real_connectors(tmp_path: Path, clean_database: None) -> None:
    asyncio.run(_run_f1(tmp_path, _mend_scanner()))


def test_f1_invicti_standard_import_to_jira_cloud_real_connectors(tmp_path: Path, clean_database: None) -> None:
    asyncio.run(_run_f1(tmp_path, _invicti_standard_scanner()))


def test_f1_uncertain_jira_create_reconciles_without_duplicate(tmp_path: Path, clean_database: None) -> None:
    asyncio.run(_run_f1(tmp_path, replace(_invicti_scanner(), uncertain_create=True)))


def test_f1_partial_mend_snapshot_preserves_source_findings(tmp_path: Path, clean_database: None) -> None:
    result = asyncio.run(_run_f1(tmp_path, _mend_scanner()))

    async def scenario() -> None:
        result.scanner.control["partial"] = True
        async with session_scope(result.tenant_id) as session:
            await trigger_sync(
                session,
                _caller(result.tenant_id),
                result.source_id,
                result.scanner.stream,
                target_id=result.target_id,
                mode="full",
            )
            job = (
                await session.execute(select(Job).where(Job.kind == "sync", Job.state == "queued"))
            ).scalars().one()
            payload = dict(job.payload_json)
        outcome = await run_sync_job(payload)
        assert outcome["outcome"] == "failed", outcome
        async with session_scope(result.tenant_id) as session:
            findings = (await session.execute(select(Finding))).scalars().all()
            assert findings and all(row.status != "resolved_by_source" for row in findings)
            latest = (
                await session.execute(select(SyncRun).order_by(SyncRun.started_at.desc()).limit(1))
            ).scalars().one()
            assert latest.outcome == "failed"
            assert latest.completeness == "partial"

    asyncio.run(scenario())
