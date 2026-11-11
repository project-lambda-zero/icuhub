"""F5 composition: GitLab MR webhooks, governed MR discussions, and CI SARIF artifact publication."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import time
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from icuhub.connectors.gitlab_self_managed import GitLabSelfManaged
from icuhub.core.actions import decide, run_apply_job, run_reconcile_job, submit_action
from icuhub.core.evidence_export import export_evidence_bundle, verify_evidence_bundle
from icuhub.core.sync import scheduler_once, trigger_sync
from icuhub.core.webhooks import create_endpoint, receive
from icuhub.kit.testing import RouteTransport
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionRequest,
    Approval,
    CaseMember,
    CorrelationCase,
    Finding,
    Job,
    RawBatch,
    Target,
    Tenant,
)
from icuhub.workers.main import run_once
from tests.core.helpers import REGISTRY, caller_for, make_services, new_connection

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "gitlab"
API = "/api/v4"
SELF_MANAGED_BASE = "https://gitlab.example.test/api/v4"
TOKEN_REF = "gitlab_token"
PROJECT_ID = 42
IID = 7
JOB_ID = 9101
WHSEC = "whsec_" + base64.b64encode(b"f5-test-key-material-0123456789").decode()
PLAN_PLACEHOLDER = "0" * 64


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _signed(delivery_id: str, body: bytes) -> dict[str, str]:
    """Standard Webhooks signature over ``{id}.{timestamp}.{body}`` using the endpoint's whsec_ key."""
    key = base64.b64decode(WHSEC.removeprefix("whsec_"))
    timestamp = str(int(time.time()))
    signed = f"{delivery_id}.{timestamp}.".encode() + body
    signature = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return {
        "webhook-id": delivery_id,
        "webhook-timestamp": timestamp,
        "webhook-signature": f"v1,{signature}",
        "x-gitlab-event": "Merge Request Hook",
    }


def _mr(head: str) -> dict[str, Any]:
    return {
        "id": 1001,
        "iid": IID,
        "project_id": PROJECT_ID,
        "state": "opened",
        "source_branch": "fix/cve-2026-1234",
        "target_branch": "main",
        "sha": head,
    }


def _sarif_archive(document: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("gl-sast-report.sarif.json", json.dumps(document).encode("utf-8"))
    return buffer.getvalue()


def _gitlab_transport(state: dict[str, Any]) -> RouteTransport:
    def read_mr(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": _mr(state["head"])}

    def list_mrs(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": _load("merge_requests_page1.json")}

    def list_discussions(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": list(state["discussions"])}

    def create_discussion(request: Any) -> dict[str, Any]:
        state["discussion_posts"] += 1
        body = json.loads(request.content)["body"]
        discussion = {
            "id": f"disc-{state['discussion_posts']}",
            "notes": [{"id": state["discussion_posts"], "body": body, "author": {"id": 7}}],
        }
        state["discussions"].append(discussion)
        return {"status": 201, "json": discussion}

    def read_job(_request: Any) -> dict[str, Any]:
        return {"status": 200, "json": dict(state["job"])}

    def play_job(_request: Any) -> dict[str, Any]:
        state["plays"] += 1
        state["job"]["status"] = "pending"
        return {"status": 201, "json": dict(state["job"])}

    def graphql(request: Any) -> dict[str, Any]:
        if state.get("native_missing"):
            body = {"data": {"project": {"vulnerabilities": {"pageInfo": {"hasNextPage": False}, "nodes": []}}}}
        else:
            variables = json.loads(request.content)["variables"]
            name = "graphql_vulnerabilities_page2.json" if variables.get("after") else "graphql_vulnerabilities_page1.json"
            body = _load(name)
        return {"status": 200, "json": body}

    def artifact(_request: Any) -> dict[str, Any]:
        if "artifact" not in state:
            return {"status": 404, "json": {"message": "artifact missing"}}
        return {"status": 200, "content": state["artifact"]}

    return RouteTransport(
        {
            ("GET", f"{API}/user"): {"status": 200, "json": {"id": 7}},
            ("GET", f"{API}/license"): {"status": 200, "json": {"plan": "ultimate"}},
            ("GET", f"{API}/projects/{PROJECT_ID}/merge_requests"): list_mrs,
            ("GET", f"{API}/projects/{PROJECT_ID}/merge_requests/{IID}"): read_mr,
            ("GET", f"{API}/projects/{PROJECT_ID}/merge_requests/{IID}/discussions"): list_discussions,
            ("POST", f"{API}/projects/{PROJECT_ID}/merge_requests/{IID}/discussions"): create_discussion,
            ("GET", f"{API}/projects/{PROJECT_ID}/jobs/{JOB_ID}"): read_job,
            ("POST", f"{API}/projects/{PROJECT_ID}/jobs/{JOB_ID}/play"): play_job,
            ("GET", f"{API}/projects/{PROJECT_ID}"): {"status": 200, "json": _load("project_42.json")},
            ("POST", "/api/graphql"): graphql,
            ("GET", f"{API}/projects/{PROJECT_ID}/jobs/{JOB_ID}/artifacts"): artifact,
        }
    )


async def _seed(services: Any, tenant_id: uuid.UUID) -> tuple[Any, str]:
    """Create the tenant, a self-managed GitLab connection, and a webhook endpoint for it."""
    async with session_scope(tenant_id) as session:
        session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="Tenant"))
        await session.flush()
        connection = await new_connection(
            session,
            services,
            tenant_id,
            kind=GitLabSelfManaged.kind,
            slug=f"gitlab-f5-{tenant_id.hex[:6]}",
            config={"base_url": SELF_MANAGED_BASE, "access_token": {"ref": TOKEN_REF}, "write_enabled": True},
            secrets={"access_token": "f5-test-token"},
        )
        endpoint_id, _ = await create_endpoint(session, caller_for(tenant_id), connection.id, secret=WHSEC)
        return connection, endpoint_id


async def _submit_approved(
    session: Any,
    tenant_id: uuid.UUID,
    connection: Any,
    action: str,
    args: dict[str, Any],
    idempotency_key: str,
    correlation_id: str | None = None,
) -> ActionRequest:
    request = await submit_action(
        session,
        caller_for(tenant_id, "requester"),
        connection.id,
        action,
        args,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
    )
    approval = (await session.execute(select(Approval).where(Approval.action_request_id == request.id))).scalar_one_or_none()
    if approval is not None:
        await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
    return request


async def _native_case(services: Any, tenant_id: uuid.UUID, connection: Any, uid: str) -> uuid.UUID:
    async with session_scope(tenant_id) as session:
        target = Target(
            tenant_id=tenant_id,
            connection_id=connection.id,
            source_uid=f"gitlab:project:{PROJECT_ID}",
            kind="project",
            display_name="example-group/demo-service",
            attributes_json={},
        )
        session.add(target)
        await session.flush()
        await trigger_sync(session, caller_for(tenant_id), connection.id, "vulnerabilities", target_id=target.id, mode="full")
    await run_once(queues=("sync", "tickets"), max_jobs=10)
    async with session_scope(tenant_id) as session:
        finding = (await session.execute(select(Finding).where(Finding.source_uid == uid))).scalars().one()
        member = (await session.execute(select(CaseMember).where(CaseMember.finding_id == finding.id))).scalars().one()
        case = await session.get(CorrelationCase, member.case_id)
        assert case is not None
        return case.id


def test_f5_repeated_delivery_and_retried_note_create_one_discussion(
    tmp_path: Any, clean_database: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(REGISTRY, GitLabSelfManaged.kind, GitLabSelfManaged)

    async def scenario() -> None:
        head = "89abcdef0123456789abcdef0123456789abcdef"
        state: dict[str, Any] = {"head": head, "discussions": [], "discussion_posts": 0}
        transport = _gitlab_transport(state)
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection, endpoint_id = await _seed(services, tenant_id)
        body = json.dumps(_load("merge_request_hook.json")).encode("utf-8")

        first = await receive(endpoint_id, _signed("f5-delivery-1", body), body)
        assert first.status_code == 202, first
        # Same delivery id replayed by the sender: deduplicated before any job is enqueued.
        replay = await receive(endpoint_id, _signed("f5-delivery-1", body), body)
        assert replay.status_code == 200, replay
        # GitLab retries under a fresh delivery id with an identical body: accepted, but no new write.
        retry = await receive(endpoint_id, _signed("f5-delivery-2", body), body)
        assert retry.status_code == 202, retry
        assert await run_once(queues=("webhooks",), max_jobs=5) == 2

        async with session_scope(tenant_id) as session:
            first_note = await _submit_approved(
                session,
                tenant_id,
                connection,
                "create_mr_note_or_discussion",
                {
                    "project_id": PROJECT_ID,
                    "iid": IID,
                    "body": "AILA scan: 1 native finding linked to this MR.",
                    "action_key": "f5-mr-note-1",
                    "approved_plan_hash": PLAN_PLACEHOLDER,
                },
                "f5-note-key-1",
            )
        applied = await run_apply_job({"action_request_id": str(first_note.id), "tenant_id": str(tenant_id)})
        assert applied["state"] == "succeeded", applied
        assert state["discussion_posts"] == 1

        # A later retry of the same logical note (new idempotency key, same action key) must find the
        # discussion already marked by the first apply and perform no second write.
        async with session_scope(tenant_id) as session:
            second_note = await _submit_approved(
                session,
                tenant_id,
                connection,
                "create_mr_note_or_discussion",
                {
                    "project_id": PROJECT_ID,
                    "iid": IID,
                    "body": "AILA scan: 1 native finding linked to this MR.",
                    "action_key": "f5-mr-note-1",
                    "approved_plan_hash": PLAN_PLACEHOLDER,
                },
                "f5-note-key-2",
            )
        await run_apply_job({"action_request_id": str(second_note.id), "tenant_id": str(tenant_id)})
        assert state["discussion_posts"] == 1
        assert len(state["discussions"]) == 1

    asyncio.run(scenario())


def test_f5_accepted_publish_never_repeats_play_while_job_is_in_flight(
    tmp_path: Any, clean_database: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(REGISTRY, GitLabSelfManaged.kind, GitLabSelfManaged)

    async def scenario() -> None:
        job = _load("job_publish_success.json")
        head = str(job["commit"]["id"])
        state: dict[str, Any] = {
            "head": head,
            "discussions": [],
            "discussion_posts": 0,
            "job": {**job, "status": "manual"},
            "plays": 0,
        }
        transport = _gitlab_transport(state)
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection, _ = await _seed(services, tenant_id)
        sarif = _load("sarif_report_with_drop.sarif.json")
        uids = [str(item["uuid"]) for item in _load("native_findings_complete.json")["items"]]
        case_id = await _native_case(services, tenant_id, connection, uids[0])

        async with session_scope(tenant_id) as session:
            request = await _submit_approved(
                session,
                tenant_id,
                connection,
                "publish_security_report_artifact",
                {
                    "project_id": PROJECT_ID,
                    "iid": IID,
                    "job_id": JOB_ID,
                    "expected_head_sha": head,
                    "sarif": sarif,
                    "native_finding_uids": uids,
                    "action_key": "f5-publish-1",
                },
                "f5-publish-key-1",
                str(case_id),
            )
        payload = {"action_request_id": str(request.id), "tenant_id": str(tenant_id)}

        # The manual job is started once; the action is accepted but not yet a publication.
        applied = await run_apply_job(payload)
        assert applied["state"] == "accepted_async", applied
        assert state["plays"] == 1

        # While the job is still running, reconciliation must observe it and leave the request alone:
        # no second play, and job success is not reported as native ingestion success.
        reconciled = await run_reconcile_job(payload)
        assert reconciled["state"] == "accepted_async", reconciled
        assert state["plays"] == 1

        state["job"]["status"] = "success"
        state["artifact"] = _sarif_archive(sarif)
        completed = await run_reconcile_job(payload)
        assert completed["state"] == "succeeded", completed
        assert state["plays"] == 1
        async with session_scope(tenant_id) as session:
            stored = await session.get(ActionRequest, request.id)
            assert stored is not None
            publication = stored.result_json["result"]
            assert publication["result_count"] == 1
            assert publication["dropped"] == [
                {"reason": "missing ruleId", "message": "Result without a rule identifier.", "uri": "src/loader.py"}
            ]
            assert publication["artifact_sha256"] == publication["sarif_sha256"]
            body = (
                f"ICUHUB published {publication['result_count']} native result; "
                f"skipped {len(publication['dropped'])}: {publication['dropped'][0]['reason']} "
                f"at {publication['dropped'][0]['uri']}."
            )
            comment = await _submit_approved(
                session,
                tenant_id,
                connection,
                "create_mr_note_or_discussion",
                {
                    "project_id": PROJECT_ID,
                    "iid": IID,
                    "body": body,
                    "action_key": "f5-publish-result-1",
                    "approved_plan_hash": PLAN_PLACEHOLDER,
                },
                "f5-publish-comment-key-1",
                str(case_id),
            )
        commented = await run_apply_job({"action_request_id": str(comment.id), "tenant_id": str(tenant_id)})
        assert commented["state"] == "succeeded", commented
        assert state["discussion_posts"] == 1
        assert "missing ruleId" in state["discussions"][0]["notes"][0]["body"]
        assert "src/loader.py" in state["discussions"][0]["notes"][0]["body"]

        signing_key = Ed25519PrivateKey.generate()
        verification_key = signing_key.public_key()
        async with session_scope(tenant_id) as session:
            bundle = await export_evidence_bundle(
                session,
                caller_for(tenant_id, "auditor-f5", roles={"auditor"}),
                case_id,
                signing_key=signing_key,
                verification_key=verification_key,
            )
        report = verify_evidence_bundle(bundle, verification_key=verification_key)
        assert report["ok"] is True, report
        evidence = bundle["payload"]
        assert evidence["correlation_case"]["id"] == str(case_id)
        assert evidence["raw_batches"]
        assert len(evidence["actions"]) == len(evidence["plans"]) == len(evidence["approvals"]) == 2
        assert {row["outcome"]["state"] for row in evidence["actions"]} == {"succeeded"}

    asyncio.run(scenario())


def test_f5_successful_ci_with_missing_native_findings_fails_without_job_write(
    tmp_path: Any, clean_database: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(REGISTRY, GitLabSelfManaged.kind, GitLabSelfManaged)

    async def scenario() -> None:
        job = _load("job_publish_success.json")
        head = str(job["commit"]["id"])
        sarif = _load("sarif_report_valid.sarif.json")
        state: dict[str, Any] = {
            "head": head,
            "discussions": [],
            "discussion_posts": 0,
            "job": {**job, "status": "success"},
            "plays": 0,
            "artifact": _sarif_archive(sarif),
            "native_missing": True,
        }
        services = make_services(_gitlab_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection, _ = await _seed(services, tenant_id)
        uids = [str(item["uuid"]) for item in _load("native_findings_complete.json")["items"]]
        async with session_scope(tenant_id) as session:
            request = await _submit_approved(
                session,
                tenant_id,
                connection,
                "publish_security_report_artifact",
                {
                    "project_id": PROJECT_ID,
                    "iid": IID,
                    "job_id": JOB_ID,
                    "expected_head_sha": head,
                    "sarif": sarif,
                    "native_finding_uids": uids,
                    "action_key": "f5-publish-missing-native",
                },
                "f5-publish-missing-native-key",
            )
        outcome = await run_apply_job({"action_request_id": str(request.id), "tenant_id": str(tenant_id)})
        assert outcome["state"] == "failed", outcome
        assert state["plays"] == 0
        assert state["discussion_posts"] == 0
        async with session_scope(tenant_id) as session:
            stored = await session.get(ActionRequest, request.id)
            assert stored is not None
            assert stored.result_json["result"]["native_missing"] == uids

    asyncio.run(scenario())


def test_f5_scheduler_and_repeated_webhooks_share_one_authoritative_sync(
    tmp_path: Any, clean_database: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(REGISTRY, GitLabSelfManaged.kind, GitLabSelfManaged)

    async def scenario() -> None:
        head = "89abcdef0123456789abcdef0123456789abcdef"
        state: dict[str, Any] = {"head": head, "discussions": [], "discussion_posts": 0}
        services = make_services(_gitlab_transport(state), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection, endpoint_id = await _seed(services, tenant_id)
        async with session_scope(tenant_id) as session:
            target = Target(
                tenant_id=tenant_id,
                connection_id=connection.id,
                source_uid=f"gitlab:project:{PROJECT_ID}",
                kind="project",
                display_name="example-group/demo-service",
                attributes_json={},
            )
            session.add(target)
            await session.flush()
            await trigger_sync(
                session, caller_for(tenant_id), connection.id, "merge_requests", target_id=target.id, mode="incremental"
            )
        await run_once(queues=("sync", "tickets"), max_jobs=10)
        scheduled = await scheduler_once(now=datetime.now(UTC) + timedelta(days=1))
        assert scheduled == 1

        event = _load("merge_request_hook.json")
        event["project"]["id"] = PROJECT_ID
        body = json.dumps(event).encode("utf-8")
        first = await receive(endpoint_id, _signed("f5-scheduled-delivery-1", body), body)
        second = await receive(endpoint_id, _signed("f5-scheduled-delivery-2", body), body)
        assert first.status_code == second.status_code == 202
        assert await run_once(queues=("webhooks",), max_jobs=5) == 2
        async with session_scope(tenant_id) as session:
            jobs = [
                job
                for job in (await session.execute(select(Job).where(Job.kind == "sync", Job.state == "queued"))).scalars()
                if job.payload_json.get("stream") == "merge_requests"
            ]
            assert len(jobs) == 1, [(job.dedupe_key, job.payload_json) for job in jobs]
        assert await run_once(queues=("sync",), max_jobs=5) == 1
        async with session_scope(tenant_id) as session:
            batches = (await session.execute(select(RawBatch).where(RawBatch.stream == "merge_requests"))).scalars().all()
            assert len({row.sync_run_id for row in batches}) == 2

    asyncio.run(scenario())
