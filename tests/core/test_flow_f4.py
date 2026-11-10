"""Flow F4: GitHub hints, authoritative PR data, governed SARIF, and evidence."""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import hmac
import json
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from icuhub.connectors._github.actions import prepare_pull_request_sarif
from icuhub.connectors._github.base import (
    GITHUB_DELIVERY_HEADER,
    GITHUB_EVENT_HEADER,
    GITHUB_SIGNATURE_HEADER,
)
from icuhub.connectors._github.models import PullRef
from icuhub.core.actions import decide, run_apply_job, run_reconcile_job, submit_action
from icuhub.core.credentials import EncryptedBlob
from icuhub.core.evidence_export import EvidenceExportError, export_evidence_bundle, verify_evidence_bundle
from icuhub.core.webhooks import create_endpoint, receive
from icuhub.kit.errors import ConfigError, StalePlan
from icuhub.kit.testing import RouteTransport
from icuhub.kit.types import MapContext
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionPlanRow,
    ActionRequest,
    Approval,
    CorrelationCase,
    Finding,
    Job,
    RawBatch,
    SyncRun,
    Tenant,
)
from icuhub.storage.models import WebhookDelivery as DeliveryRow
from icuhub.workers.main import run_once
from tests.core.helpers import caller_for, make_services, new_connection

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "github"
BASE = "https://api.github.com"
REPO_PATH = "/repos/example-org/example-repo"
PULL_PATH = f"{REPO_PATH}/pulls/7"
FILES_PATH = f"{PULL_PATH}/files"
REF_PATH = f"{REPO_PATH}/git/ref/pull/7/head"
COMMENTS_PATH = f"{REPO_PATH}/issues/7/comments"
COMMENT_PATH = f"{REPO_PATH}/issues/comments/12"
SARIF_PATH = f"{REPO_PATH}/code-scanning/sarifs"
SARIF_STATUS_PATH = f"{SARIF_PATH}/sarif-1001"
ANALYSIS_PATH = f"{REPO_PATH}/code-scanning/analyses/501"
CHECKS_PATH = f"{REPO_PATH}/check-runs"
CHECK_LIST_PATH = f"{REPO_PATH}/commits/{'a1b2c3d4' * 5}/check-runs"
CHECK_PATH = f"{CHECKS_PATH}/77"
APP_TOKEN_PATH = "/app/installations/67890/access_tokens"
HEAD_SHA = "a1b2c3d4" * 5
CHANGED_HEAD_SHA = "b2c3d4e5" * 5
BASE_SHA = "c3d4e5f6" * 5
SARIF_ID = "sarif-1001"
ANALYSIS_ID = 501


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _state() -> dict[str, Any]:
    pull = _load("pull_request_open.json")
    pull["title"] = "Authoritative vendor pull"
    pull["head"] = {"ref": "feature-branch", "sha": HEAD_SHA}
    pull["base"] = {"ref": "main", "sha": BASE_SHA}
    return {
        "repositories": _load("repositories_page1.json"),
        "pull": pull,
        "files": [
            {
                "filename": "src/app.py",
                "patch": "@@ -11,2 +11,3 @@\n first\n+added\n last",
            }
        ],
        "comments": [],
        "checks": [],
        "sarif_acceptance": {
            "id": SARIF_ID,
            "analysis_id": ANALYSIS_ID,
            "created_at": "2026-11-10T12:00:00Z",
        },
        "processing_status": "failed",
        "processing_errors": [{"message": "synthetic processing failure"}],
        "analysis": {
            "id": ANALYSIS_ID,
            "commit_sha": HEAD_SHA,
            "ref": "refs/pull/7/head",
            "created_at": "2026-11-10T12:00:00Z",
            "processing_status": "complete",
            "results_count": 1,
            "rules_count": 1,
            "tool": {"name": "Synthetic Scanner"},
        },
    }


def _transport(state: dict[str, Any]) -> RouteTransport:
    def create_comment(request: Any) -> dict[str, Any]:
        payload = json.loads(request.content)
        comment = {
            "id": 12,
            "body": payload["body"],
            "url": f"{BASE}{COMMENT_PATH}",
        }
        state["comments"].append(comment)
        return {"status": 201, "json": comment}

    def create_check(request: Any) -> dict[str, Any]:
        payload = json.loads(request.content)
        check = {"id": 77, **payload}
        state["checks"].append(check)
        return {"status": 201, "json": check}

    routes = {
        ("GET", "/user/repos"): lambda _request: {"status": 200, "json": state["repositories"]},
        ("GET", f"{REPO_PATH}/pulls"): lambda _request: {"status": 200, "json": [state["pull"]]},
        ("GET", PULL_PATH): lambda _request: {"status": 200, "json": state["pull"]},
        ("GET", FILES_PATH): lambda _request: {"status": 200, "json": state["files"]},
        ("GET", REF_PATH): lambda _request: {
            "status": 200,
            "json": {"object": {"sha": state["pull"]["head"]["sha"]}},
        },
        ("GET", COMMENTS_PATH): lambda _request: {"status": 200, "json": state["comments"]},
        ("POST", COMMENTS_PATH): create_comment,
        ("GET", COMMENT_PATH): lambda _request: {"status": 200, "json": state["comments"][0]},
        ("POST", SARIF_PATH): lambda _request: {"status": 202, "json": state["sarif_acceptance"]},
        ("GET", SARIF_STATUS_PATH): lambda _request: {
            "status": 200,
            "json": {
                "processing_status": state["processing_status"],
                "analysis_id": ANALYSIS_ID,
                "errors": state["processing_errors"],
            },
        },
        ("GET", ANALYSIS_PATH): lambda _request: {"status": 200, "json": state["analysis"]},
        ("GET", CHECK_LIST_PATH): lambda _request: {"status": 200, "json": {"check_runs": state["checks"]}},
        ("POST", CHECKS_PATH): create_check,
        ("GET", CHECK_PATH): lambda _request: {"status": 200, "json": state["checks"][0]},
        ("POST", APP_TOKEN_PATH): {
            "status": 201,
            "json": {"token": "synthetic-installation-token", "expires_at": "2099-01-01T00:00:00+00:00"},
        },
    }
    return RouteTransport(routes)


async def _new_github(
    services: Any,
    tenant_id: uuid.UUID,
    *,
    slug: str = "github-f4",
    app_private_key: str | None = None,
) -> Any:
    async with session_scope(tenant_id) as session:
        session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="Tenant"))
        await session.flush()
        if app_private_key is None:
            config = {
                "base_url": BASE,
                "personal_access_token": {"ref": "github-pat"},
                "write_enabled": True,
            }
            secrets = {"personal_access_token": "synthetic-pat"}
        else:
            config = {
                "base_url": BASE,
                "app_id": "12345",
                "app_private_key": {"ref": "github-app-key"},
                "installation_id": "67890",
                "write_enabled": True,
            }
            secrets = {"app_private_key": app_private_key}
        return await new_connection(
            session,
            services,
            tenant_id,
            kind="github",
            slug=slug,
            config=config,
            secrets=secrets,
        )


async def _approve(session: Any, tenant_id: uuid.UUID, request: ActionRequest) -> None:
    approval = (
        await session.execute(select(Approval).where(Approval.action_request_id == request.id))
    ).scalar_one()
    await decide(session, caller_for(tenant_id, "approver", roles={"approver"}), approval.id, "approved")
    assert request.state == "approved"


async def _submit_approved(
    session: Any,
    tenant_id: uuid.UUID,
    connection: Any,
    action: str,
    args: dict[str, Any],
    idempotency_key: str,
    *,
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
    await _approve(session, tenant_id, request)
    return request


def _calls(transport: RouteTransport, method: str, path: str) -> list[Any]:
    return [
        request
        for request in transport.requests
        if request.method == method and request.url.path == path
    ]


def _webhook_body() -> bytes:
    pull = _load("pull_request_open.json")
    pull["title"] = "Webhook supplied title must not persist"
    pull["head"] = {"ref": "webhook-branch", "sha": "f" * 40}
    return json.dumps(
        {
            "action": "opened",
            "repository": {
                "id": 1001,
                "name": "example-repo",
                "full_name": "example-org/example-repo",
                "owner": {"login": "example-org"},
            },
            "pull_request": pull,
        },
        separators=(",", ":"),
    ).encode()


def _signed_headers(secret: str, body: bytes, delivery: str) -> dict[str, str]:
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        GITHUB_SIGNATURE_HEADER: f"sha256={signature}",
        GITHUB_DELIVERY_HEADER: delivery,
        GITHUB_EVENT_HEADER: "pull_request",
    }


def _sarif_args() -> dict[str, Any]:
    return {
        "owner": "example-org",
        "repo": "example-repo",
        "commit_sha": HEAD_SHA,
        "ref": "refs/pull/7/head",
        "tool_name": "Synthetic Scanner",
        "sarif": {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Synthetic Scanner"}},
                    "results": [
                        {
                            "ruleId": "CWE-89",
                            "message": {"text": "Synthetic finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {"startLine": 12, "endLine": 12},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    }


async def _prepare_pr_sarif(services: Any, session: Any, tenant_id: uuid.UUID, connection: Any) -> dict[str, Any]:
    connector = await services.runtime.open(session, tenant_id, connection.id)
    context = MapContext(
        connection_id=str(connection.id),
        tenant_id=str(tenant_id),
        connector_kind=connector.kind,
        target=None,
        received_at=datetime.now(UTC),
    )

    def mapped_finding(number: int, line: int | None) -> Any:
        raw = deepcopy(_load("alert_open.json"))
        raw["_repository_id"] = 1001
        raw["number"] = number
        if line is None:
            raw["most_recent_instance"]["location"] = {}
        else:
            raw["most_recent_instance"]["location"]["start_line"] = line
            raw["most_recent_instance"]["location"]["end_line"] = line
        mapper = connector.mappers()["code_scanning_alerts"]
        return mapper.fn(connector, raw, context)[0]

    findings = [mapped_finding(4, 12), mapped_finding(5, 99), mapped_finding(6, None)]
    return await prepare_pull_request_sarif(
        connector,
        PullRef(owner="example-org", repo="example-repo", pull_number=7),
        findings,
        "Synthetic Scanner",
    )


def test_pr_webhook_is_hint_only(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _state()
        transport = _transport(state)
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection = await _new_github(services, tenant_id)
        async with session_scope(tenant_id) as session:
            targets = await services.runtime.discover_targets(session, caller_for(tenant_id), connection.id)
            assert len(targets) == 1
            target = targets[0]
            assert target.source_uid == "1001"
            assert target.kind == "repository"
            assert target.display_name == "example-org/example-repo"
            assert target.attributes_json == {
                "owner": "example-org",
                "repo": "example-repo",
                "full_name": "example-org/example-repo",
            }
            endpoint_id, secret = await create_endpoint(
                session,
                caller_for(tenant_id),
                connection.id,
                secret="synthetic-webhook-secret",
            )
        body = _webhook_body()
        receipt = await receive(endpoint_id, _signed_headers(secret, body, "delivery-f4-pr"), body)
        assert receipt.status_code == 202
        assert await run_once(queues=("webhooks", "sync"), max_jobs=4) >= 2
        async with session_scope(tenant_id) as session:
            delivery = (await session.execute(select(DeliveryRow))).scalar_one()
            assert delivery.status == "processed"
            sync_job = (await session.execute(select(Job).where(Job.queue == "sync"))).scalar_one()
            assert sync_job.payload_json["target_id"] == str(target.id)
            sync_run = (
                await session.execute(select(SyncRun).where(SyncRun.stream == "pull_requests"))
            ).scalar_one()
            assert sync_run.outcome == "succeeded", (sync_run.error_class, sync_run.error_detail)
            assert list((await session.scalars(select(Finding))).all()) == []
            raw = (
                await session.execute(
                    select(RawBatch).where(
                        RawBatch.origin == "stream",
                        RawBatch.stream == "pull_requests",
                        RawBatch.record_count > 0,
                    )
                )
            ).scalar_one()
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
            records = json.loads(payload)
            assert raw.record_count == 1
            assert records[0]["title"] == "Authoritative vendor pull"
            assert records[0]["head"]["sha"] == HEAD_SHA
            assert "Webhook supplied title must not persist" not in json.dumps(records)
            assert "f" * 40 not in json.dumps(records)
            prepared = await _prepare_pr_sarif(services, session, tenant_id, connection)
            assert prepared["metadata"]["head_sha"] == HEAD_SHA
            assert prepared["upload_args"]["commit_sha"] == HEAD_SHA
        assert len(_calls(transport, "GET", f"{REPO_PATH}/pulls")) == 1
        assert len(_calls(transport, "GET", PULL_PATH)) == 1
        assert len(_calls(transport, "GET", FILES_PATH)) == 1

    asyncio.run(scenario())


def test_sarif_skipped_reasons_no_fabricated_locations(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _state()
        transport = _transport(state)
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection = await _new_github(services, tenant_id)
        async with session_scope(tenant_id) as session:
            prepared = await _prepare_pr_sarif(services, session, tenant_id, connection)
            assert {item["reason"] for item in prepared["skipped"]} == {
                "no_code_location",
                "outside_current_diff",
            }
            args = prepared["upload_args"]
            args["sarif"]["runs"][0]["results"].append(
                {"ruleId": "synthetic/missing-location", "message": {"text": "No location"}}
            )
            request = await _submit_approved(
                session,
                tenant_id,
                connection,
                "upload_code_scanning_sarif",
                args,
                "f4-sarif-locations",
            )
            plan = await session.get(ActionPlanRow, request.id)
            assert plan is not None
            assert {item["reason"] for item in plan.request_json["skipped"]} == {"missing_location"}
        assert await run_once(queues=("actions",), max_jobs=1) == 1
        posts = _calls(transport, "POST", SARIF_PATH)
        assert len(posts) == 1
        upload = json.loads(posts[0].content)
        assert upload["commit_sha"] == HEAD_SHA
        assert upload["ref"] == "refs/pull/7/head"
        document = json.loads(gzip.decompress(base64.b64decode(upload["sarif"])))
        assert document["version"] == "2.1.0"
        emitted_locations = {
            (
                location["physicalLocation"]["artifactLocation"]["uri"],
                location["physicalLocation"]["region"]["startLine"],
            )
            for run in document["runs"]
            for result in run["results"]
            for location in result["locations"]
        }
        assert emitted_locations == {("src/app.py", 12)}
        assert all(
            result["ruleId"] != "synthetic/missing-location"
            for run in document["runs"]
            for result in run["results"]
        )

    asyncio.run(scenario())


def test_upload_persists_analysis_id_and_accepted_then_failed_is_failed(
    tmp_path: Any, clean_database: None
) -> None:
    async def scenario() -> None:
        state = _state()
        transport = _transport(state)
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection = await _new_github(services, tenant_id)
        async with session_scope(tenant_id) as session:
            request = await _submit_approved(
                session,
                tenant_id,
                connection,
                "upload_code_scanning_sarif",
                _sarif_args(),
                "f4-sarif-failed",
            )
        payload = {"action_request_id": str(request.id), "tenant_id": str(tenant_id)}
        applied = await run_apply_job(payload)
        assert applied["state"] == "accepted_async"
        async with session_scope(tenant_id) as session:
            accepted = await session.get(ActionRequest, request.id)
            assert accepted is not None
            assert accepted.result_json["vendor_ref"] == SARIF_ID
            assert accepted.result_json["result"]["sarif_id"] == SARIF_ID
            assert accepted.result_json["result"]["analysis_id"] == ANALYSIS_ID
        state["processing_status"] = "failed"
        reconciled = await run_reconcile_job(payload)
        assert reconciled["state"] == "failed"
        async with session_scope(tenant_id) as session:
            failed = await session.get(ActionRequest, request.id)
            assert failed is not None
            assert failed.state == "failed"
            assert failed.result_json["vendor_ref"] == SARIF_ID
            assert failed.result_json["result"]["processing_status"] == "failed"
        assert len(_calls(transport, "POST", SARIF_PATH)) == 1
        post_paths = [request.url.path for request in transport.requests if request.method == "POST"]
        assert post_paths == [SARIF_PATH]
        assert _calls(transport, "POST", CHECKS_PATH) == []

    asyncio.run(scenario())


def test_native_readback_gates_check(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _state()
        transport = _transport(state)
        services = make_services(transport, tmp_path / "kek")
        pat_tenant = uuid.uuid4()
        pat_connection = await _new_github(services, pat_tenant, slug="github-pat-f4")
        check_args = {
            "owner": "example-org",
            "repo": "example-repo",
            "sha": HEAD_SHA,
            "name": "icuhub",
            "action_key": "icuhub:check-f4",
            "analysis_id": ANALYSIS_ID,
            "status": "completed",
            "conclusion": "success",
            "title": "Synthetic scan",
            "summary": "Authoritative analysis reconciled",
        }
        async with session_scope(pat_tenant) as session:
            with pytest.raises(ConfigError, match="require GitHub App authentication"):
                await submit_action(
                    session,
                    caller_for(pat_tenant, "requester"),
                    pat_connection.id,
                    "create_or_update_check_run",
                    check_args,
                    idempotency_key="f4-pat-check-refused",
                )
        assert _calls(transport, "POST", CHECKS_PATH) == []

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        app_tenant = uuid.uuid4()
        app_connection = await _new_github(
            services,
            app_tenant,
            slug="github-app-f4",
            app_private_key=private_pem,
        )
        state["analysis"]["processing_status"] = "pending"
        async with session_scope(app_tenant) as session:
            with pytest.raises(StalePlan, match="not terminal"):
                await submit_action(
                    session,
                    caller_for(app_tenant, "requester"),
                    app_connection.id,
                    "create_or_update_check_run",
                    check_args,
                    idempotency_key="f4-app-check-pending",
                )
        assert _calls(transport, "POST", CHECKS_PATH) == []

        state["analysis"]["processing_status"] = "complete"
        state["analysis"]["commit_sha"] = HEAD_SHA
        async with session_scope(app_tenant) as session:
            request = await _submit_approved(
                session,
                app_tenant,
                app_connection,
                "create_or_update_check_run",
                check_args,
                "f4-app-check-terminal",
            )
        applied = await run_apply_job({"action_request_id": str(request.id), "tenant_id": str(app_tenant)})
        assert applied["state"] == "succeeded"
        check_posts = _calls(transport, "POST", CHECKS_PATH)
        assert len(check_posts) == 1
        analysis_reads = _calls(transport, "GET", ANALYSIS_PATH)
        assert len(analysis_reads) >= 2
        request_order = list(transport.requests)
        assert request_order.index(analysis_reads[-1]) < request_order.index(check_posts[0])
        assert state["analysis"]["processing_status"] == "complete"
        assert state["analysis"]["commit_sha"] == HEAD_SHA
        assert len(state["checks"]) == 1
        assert state["checks"][0]["head_sha"] == HEAD_SHA

    asyncio.run(scenario())


def test_repeated_comment_review_delivery_no_duplicate(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _state()
        transport = _transport(state)
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection = await _new_github(services, tenant_id)
        args = {
            "owner": "example-org",
            "repo": "example-repo",
            "pull_number": 7,
            "body": "Synthetic review comment",
            "action_key": "icuhub:comment-f4",
        }
        async with session_scope(tenant_id) as session:
            first = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_pr_comment",
                args,
                idempotency_key="f4-comment-duplicate",
            )
            replay = await submit_action(
                session,
                caller_for(tenant_id, "requester"),
                connection.id,
                "create_pr_comment",
                args,
                idempotency_key="f4-comment-duplicate",
            )
            assert replay.id == first.id
            assert len(list((await session.scalars(select(ActionRequest))).all())) == 1
            await _approve(session, tenant_id, first)
        applied = await run_apply_job({"action_request_id": str(first.id), "tenant_id": str(tenant_id)})
        assert applied["state"] == "succeeded"
        assert len(_calls(transport, "POST", COMMENTS_PATH)) == 1
        async with session_scope(tenant_id) as session:
            endpoint_id, secret = await create_endpoint(
                session,
                caller_for(tenant_id),
                connection.id,
                secret="synthetic-webhook-secret",
            )
        body = _webhook_body()
        headers = _signed_headers(secret, body, "delivery-f4-duplicate")
        first_receipt = await receive(endpoint_id, headers, body)
        duplicate_receipt = await receive(endpoint_id, headers, body)
        assert first_receipt.status_code == 202
        assert duplicate_receipt.status_code == 200
        assert duplicate_receipt.detail == "duplicate"
        async with session_scope(tenant_id) as session:
            deliveries = list((await session.scalars(select(DeliveryRow))).all())
            assert len(deliveries) == 1
            assert deliveries[0].vendor_delivery_id == "delivery-f4-duplicate"
        assert len(_calls(transport, "POST", COMMENTS_PATH)) == 1

    asyncio.run(scenario())


def test_head_change_yields_stale_plan(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _state()
        transport = _transport(state)
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection = await _new_github(services, tenant_id)
        async with session_scope(tenant_id) as session:
            request = await _submit_approved(
                session,
                tenant_id,
                connection,
                "upload_code_scanning_sarif",
                _sarif_args(),
                "f4-sarif-stale",
            )
        writes_before = len([item for item in transport.requests if item.method == "POST"])
        state["pull"]["head"]["sha"] = CHANGED_HEAD_SHA
        outcome = await run_apply_job({"action_request_id": str(request.id), "tenant_id": str(tenant_id)})
        assert outcome["state"] == "stale_plan"
        writes_after = len([item for item in transport.requests if item.method == "POST"])
        assert writes_after == writes_before
        assert _calls(transport, "POST", SARIF_PATH) == []
        async with session_scope(tenant_id) as session:
            stale = await session.get(ActionRequest, request.id)
            assert stale is not None
            assert stale.state == "stale_plan"
            assert stale.error_class == "StalePlan"

    asyncio.run(scenario())


def test_signed_evidence_export_and_cross_tenant_denied(tmp_path: Any, clean_database: None) -> None:
    async def scenario() -> None:
        state = _state()
        transport = _transport(state)
        services = make_services(transport, tmp_path / "kek")
        tenant_id = uuid.uuid4()
        connection = await _new_github(services, tenant_id)
        case_id = uuid.uuid4()
        args = {
            "owner": "example-org",
            "repo": "example-repo",
            "pull_number": 7,
            "body": "Evidence review comment",
            "action_key": "icuhub:evidence-f4",
        }
        async with session_scope(tenant_id) as session:
            session.add(
                CorrelationCase(
                    id=case_id,
                    tenant_id=tenant_id,
                    correlation_key=f"v1|own|{case_id}",
                    key_version=1,
                    title="F4 evidence case",
                    severity_id=1,
                )
            )
            await session.flush()
            request = await _submit_approved(
                session,
                tenant_id,
                connection,
                "create_pr_comment",
                args,
                "f4-evidence-comment",
                correlation_id=str(case_id),
            )
        applied = await run_apply_job({"action_request_id": str(request.id), "tenant_id": str(tenant_id)})
        assert applied["state"] == "succeeded"
        signing_key = Ed25519PrivateKey.generate()
        verification_key = signing_key.public_key()
        async with session_scope(tenant_id) as session:
            bundle = await export_evidence_bundle(
                session,
                caller_for(tenant_id, "auditor-f4", roles={"auditor"}),
                case_id,
                signing_key=signing_key,
                verification_key=verification_key,
            )
        report = verify_evidence_bundle(bundle, verification_key=verification_key)
        assert report["ok"] is True, report
        payload = bundle["payload"]
        assert payload["correlation_case"]["id"] == str(case_id)
        assert len(payload["actions"]) == 1
        assert payload["actions"][0]["id"] == str(request.id)
        assert payload["actions"][0]["outcome"]["state"] == "succeeded"
        assert payload["actions"][0]["outcome"]["result"]["sha256"].startswith("sha256:")
        assert len(payload["plans"]) == 1
        assert payload["plans"][0]["action_request_id"] == str(request.id)
        assert len(payload["approvals"]) == 1
        assert payload["approvals"][0]["decision"] == "approved"
        assert payload["vendor_references"] == [
            {"kind": "action_outcome", "value": "12", "action_request_id": str(request.id)}
        ]

        foreign_tenant = uuid.uuid4()
        async with session_scope(foreign_tenant) as session:
            session.add(
                Tenant(id=foreign_tenant, slug=f"t-{foreign_tenant.hex[:8]}", display_name="Other")
            )
            await session.flush()
            with pytest.raises(EvidenceExportError):
                await export_evidence_bundle(
                    session,
                    caller_for(foreign_tenant, "foreign-auditor", roles={"auditor"}),
                    case_id,
                    signing_key=signing_key,
                    verification_key=verification_key,
                )

    asyncio.run(scenario())
