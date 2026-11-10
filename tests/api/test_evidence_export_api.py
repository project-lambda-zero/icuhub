"""F7 evidence export through the real ASGI application and PostgreSQL RLS."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from icuhub.api.app import create_app
from icuhub.api.auth import api_key_hash
from icuhub.core.audit import append as audit_append
from icuhub.core.audit import verify_chain
from icuhub.core.evidence_export import load_verification_key, verify_evidence_bundle
from icuhub.settings import get_settings
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionPlanRow,
    ActionRequest,
    Approval,
    AuditRecord,
    CaseMember,
    Connection,
    CorrelationCase,
    EvidenceItem,
    FileImport,
    Finding,
    PolicyRule,
    RawBatch,
    ServiceAccount,
    Tenant,
    TicketLink,
    TicketRoute,
)

AUDITOR_TOKEN = "icuhub_audit0001_secret"
OPERATOR_TOKEN = "icuhub_opera0001_secret"
FOREIGN_TOKEN = "icuhub_other0001_secret"


def _auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def _account(tenant_id: uuid.UUID, account_id: uuid.UUID, name: str, token: str, roles: list[str]) -> ServiceAccount:
    return ServiceAccount(
        id=account_id,
        tenant_id=tenant_id,
        name=name,
        key_prefix=token[:16],
        key_hash=api_key_hash(token),
        roles=roles,
        groups=["secops"],
    )


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()


def _resign(bundle: dict[str, Any], signing_key: Ed25519PrivateKey) -> None:
    payload = _canonical(bundle["payload"])
    bundle["payload_digest"] = _sha(payload)
    bundle["signature"]["signature"] = base64.b64encode(signing_key.sign(payload)).decode("ascii")


@pytest.fixture
def evidence_api(tmp_path: Path, clean_database: None, monkeypatch: pytest.MonkeyPatch) -> Any:
    tenant_id = uuid.uuid4()
    foreign_tenant_id = uuid.uuid4()
    case_id = uuid.uuid4()
    auditor_id = uuid.uuid4()
    connection_id = uuid.uuid4()
    raw_batch_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    file_import_id = uuid.uuid4()
    action_id = uuid.uuid4()
    approval_id = uuid.uuid4()
    route_id = uuid.uuid4()
    policy_rule_id = uuid.uuid4()
    signing_key = Ed25519PrivateKey.generate()
    verification_key = signing_key.public_key()
    signing_path = tmp_path / "signing.pem"
    verification_path = tmp_path / "verification.pem"
    signing_path.write_bytes(
        signing_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    verification_path.write_bytes(
        verification_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv("ICUHUB_EVIDENCE_SIGNING_KEY_FILE", str(signing_path))
    monkeypatch.setenv("ICUHUB_EVIDENCE_VERIFICATION_KEY_FILE", str(verification_path))
    get_settings.cache_clear()

    raw_digest = _sha(b"encrypted source reference")
    file_digest = _sha(b"bounded import reference")
    plan_hash = _sha(b"action plan")
    args_digest = _sha(b"action arguments")
    now = datetime.now(UTC)

    async def seed() -> None:
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex[:8]}", display_name="Tenant"))
            await session.flush()
            for row in [
                    _account(tenant_id, auditor_id, "auditor", AUDITOR_TOKEN, ["auditor"]),
                    _account(tenant_id, uuid.uuid4(), "operator", OPERATOR_TOKEN, ["operator"]),
                    Connection(
                        id=connection_id,
                        tenant_id=tenant_id,
                        kind="sample",
                        slug="source",
                        display_name="Source",
                        config_json={"api_token": "connection-secret", "credential": "cred:private"},
                        allowed_operations=["remediate"],
                    ),
                    CorrelationCase(
                        id=case_id,
                        tenant_id=tenant_id,
                        correlation_key="v1|cve|CVE-2026-0001|host:asset-1",
                        key_version=1,
                        title="Evidence case",
                        severity_id=4,
                    ),
                    RawBatch(
                        id=raw_batch_id,
                        tenant_id=tenant_id,
                        connection_id=connection_id,
                        origin="stream",
                        stream="findings",
                        digest=raw_digest,
                        record_count=1,
                        parser_version="1",
                        kek_id="local",
                        dek_wrapped=b"wrapped",
                        nonce=b"nonce-value",
                        payload_enc=b"encrypted-payload",
                        expires_at=now + timedelta(days=1),
                    ),
                    FileImport(
                        id=file_import_id,
                        tenant_id=tenant_id,
                        connection_id=connection_id,
                        importer="sample",
                        filename="report.json",
                        digest=file_digest,
                        size_bytes=1024,
                        state="done",
                        raw_batch_id=raw_batch_id,
                        counts_json={"accepted": 1},
                    ),
                    Finding(
                        id=finding_id,
                        tenant_id=tenant_id,
                        connection_id=connection_id,
                        stream="findings",
                        source_uid="finding-1",
                        fingerprint="finding-fingerprint",
                        ocsf_class_uid=2002,
                        severity_id=4,
                        title="Finding",
                        ocsf_json={"class_uid": 2002, "credentials": {"api_token": "finding-secret"}},
                        revision_digest=_sha(b"finding revision"),
                        raw_batch_id=raw_batch_id,
                        mapper_version=1,
                        correlation_key="v1|cve|CVE-2026-0001|host:asset-1",
                    ),
                    CaseMember(
                        finding_id=finding_id,
                        tenant_id=tenant_id,
                        case_id=case_id,
                        reason="key_match",
                        linked_by="correlation",
                    ),
                    PolicyRule(
                        id=policy_rule_id,
                        tenant_id=tenant_id,
                        priority=10,
                        name="Approval required",
                        match_json={"operations": ["remediate"]},
                        decision="require_approval",
                        approver_group="secops",
                    ),
                    ActionRequest(
                        id=action_id,
                        tenant_id=tenant_id,
                        connection_id=connection_id,
                        action="remediate",
                        classification="write",
                        args_json={"password": "argument-secret"},
                        args_digest=args_digest,
                        caller_id="operator",
                        correlation_id=str(case_id),
                        idempotency_key="action-1",
                        state="succeeded",
                        decision="require_approval",
                        rule_id=policy_rule_id,
                        result_json={
                            "vendor_ref": "VEND-1",
                            "password": "outcome-secret",
                            "details": "x" * 20000,
                        },
                    ),
                    ActionPlanRow(
                        action_request_id=action_id,
                        tenant_id=tenant_id,
                        target_ref="asset-1",
                        diff_json={"private_key": "plan-secret"},
                        preconditions_json={"revision": "1"},
                        request_json={"headers": {"Authorization": "Bearer request-secret"}},
                        idempotency_key="action-1",
                        plan_hash=plan_hash,
                        changed=True,
                    ),
                    Approval(
                        id=approval_id,
                        tenant_id=tenant_id,
                        action_request_id=action_id,
                        approver_group="secops",
                        plan_hash=plan_hash,
                        expires_at=now + timedelta(hours=1),
                        decision="approved",
                        decided_by="approver",
                        decided_at=now,
                        reason="Reviewed",
                    ),
                    TicketRoute(
                        id=route_id,
                        tenant_id=tenant_id,
                        name="route",
                        connection_id=connection_id,
                        action="create_issue",
                        match_json={"min_severity_id": 4},
                        template_json={"secret": "route-secret"},
                    ),
                    TicketLink(
                        tenant_id=tenant_id,
                        route_id=route_id,
                        case_id=case_id,
                        connection_id=connection_id,
                        state="succeeded",
                        remote_key="VEND-1",
                        remote_id="remote-1",
                        remote_url="https://vendor.example.test/VEND-1",
                        remote_status="open",
                        status_category="open",
                        action_request_id=action_id,
                    ),
                ]:
                session.add(row)
                await session.flush()
            session.add_all(
                [
                    EvidenceItem(
                        tenant_id=tenant_id,
                        case_id=case_id,
                        kind="raw_batch",
                        digest=raw_digest,
                        ref_table="raw_batch",
                        ref_id=raw_batch_id,
                    ),
                    EvidenceItem(
                        tenant_id=tenant_id,
                        case_id=case_id,
                        kind="file_import",
                        digest=file_digest,
                        ref_table="file_import",
                        ref_id=file_import_id,
                    ),
                    EvidenceItem(
                        tenant_id=tenant_id,
                        case_id=case_id,
                        kind="action_plan",
                        digest=plan_hash,
                        ref_table="action_plan",
                        ref_id=action_id,
                    ),
                ]
            )
            await audit_append(
                session,
                tenant_id,
                ts=now,
                caller_id="operator",
                connection_id=connection_id,
                operation="action.remediate",
                classification="write",
                decision="require_approval",
                approval_id=approval_id,
                args_digest=args_digest,
                status="succeeded",
                correlation_id=str(case_id),
                detail_json={"case_id": str(case_id), "state": "succeeded"},
            )
        async with session_scope(foreign_tenant_id) as session:
            session.add(
                Tenant(id=foreign_tenant_id, slug=f"tenant-{foreign_tenant_id.hex[:8]}", display_name="Other")
            )
            await session.flush()
            session.add(_account(foreign_tenant_id, uuid.uuid4(), "auditor", FOREIGN_TOKEN, ["auditor"]))

    asyncio.run(seed())
    yield {
        "app": create_app(),
        "tenant_id": tenant_id,
        "foreign_tenant_id": foreign_tenant_id,
        "case_id": case_id,
        "auditor_id": auditor_id,
        "verification_path": verification_path,
        "signing_key": signing_key,
        "raw_digest": raw_digest,
        "file_digest": file_digest,
        "plan_hash": plan_hash,
    }
    get_settings.cache_clear()


def _audit_count(tenant_id: uuid.UUID, operation: str) -> int:
    async def scenario() -> int:
        async with session_scope(tenant_id) as session:
            return int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(AuditRecord)
                        .where(AuditRecord.operation == operation)
                    )
                ).scalar_one()
            )

    return asyncio.run(scenario())


def test_auditor_exports_complete_signed_bundle_and_audit_chain(asgi: Any, evidence_api: dict[str, Any]) -> None:
    call = asgi(evidence_api["app"])
    status, _, body = call(
        "GET", f"/v1/cases/{evidence_api['case_id']}/evidence-export", _auth(AUDITOR_TOKEN)
    )
    assert status == 200, body
    bundle = json.loads(body)
    verification_key = load_verification_key(evidence_api["verification_path"])
    report = verify_evidence_bundle(bundle, verification_key=verification_key)
    assert report["ok"] is True, report

    payload = bundle["payload"]
    assert payload["caller"] == {
        "id": str(evidence_api["auditor_id"]),
        "kind": "service_account",
        "roles": ["auditor"],
        "groups": ["secops"],
    }
    assert payload["tenant"]["id"] == str(evidence_api["tenant_id"])
    assert payload["correlation_case"]["id"] == str(evidence_api["case_id"])
    assert len(payload["case_members"]) == 1
    assert len(payload["findings"]) == 1
    assert len(payload["connections"]) == 1
    assert payload["ticket_links"][0]["remote_key"] == "VEND-1"
    assert payload["vendor_references"][0]["value"] == "VEND-1"
    assert payload["plans"][0]["plan_hash"] == evidence_api["plan_hash"]
    assert payload["approvals"][0]["decision"] == "approved"
    assert payload["policy_decisions"][0]["decision"] == "require_approval"
    assert payload["actions"][0]["outcome"]["state"] == "succeeded"
    assert payload["actions"][0]["outcome"]["result"]["truncated"] is True
    assert payload["actions"][0]["outcome"]["result"]["content"] is None
    assert {row["digest"] for row in payload["raw_batches"]} == {evidence_api["raw_digest"]}
    assert {row["digest"] for row in payload["file_imports"]} == {evidence_api["file_digest"]}
    assert len(payload["evidence"]) == 3
    assert report["evidence_references"]["checked"] == 3
    assert payload["audit"]["records"][-1]["operation"] == "evidence.export"
    assert payload["audit"]["records"][-1]["classification"] == "read"
    assert payload["audit"]["chain"]["ok"] is True

    encoded = json.dumps(bundle)
    for secret in (
        "connection-secret",
        "finding-secret",
        "argument-secret",
        "outcome-secret",
        "plan-secret",
        "request-secret",
        "route-secret",
        "x" * 20000,
    ):
        assert secret not in encoded
    assert "payload_enc" not in encoded
    assert "dek_wrapped" not in encoded
    assert "private_key" not in bundle["signature"]

    assert _audit_count(evidence_api["tenant_id"], "evidence.export") == 1

    async def chain() -> None:
        async with session_scope(evidence_api["tenant_id"]) as session:
            result = await verify_chain(session, evidence_api["tenant_id"])
            assert result.ok is True

    asyncio.run(chain())


def test_resigned_evidence_digest_tamper_is_detected_offline(asgi: Any, evidence_api: dict[str, Any]) -> None:
    call = asgi(evidence_api["app"])
    status, _, body = call(
        "GET", f"/v1/cases/{evidence_api['case_id']}/evidence-export", _auth(AUDITOR_TOKEN)
    )
    assert status == 200, body
    bundle = json.loads(body)
    bundle["payload"]["raw_batches"][0]["digest"] = _sha(b"tampered")
    _resign(bundle, evidence_api["signing_key"])

    report = verify_evidence_bundle(
        bundle, verification_key=load_verification_key(evidence_api["verification_path"])
    )
    assert report["ok"] is False
    assert "evidence_reference_invalid" in report["failures"]


def test_role_and_cross_tenant_denial_do_not_export_or_leak(asgi: Any, evidence_api: dict[str, Any]) -> None:
    call = asgi(evidence_api["app"])
    path = f"/v1/cases/{evidence_api['case_id']}/evidence-export"

    status, _, body = call("GET", path, _auth(OPERATOR_TOKEN))
    assert status == 403, body
    assert _audit_count(evidence_api["tenant_id"], "evidence.export") == 0

    foreign_status, _, foreign_body = call("GET", path, _auth(FOREIGN_TOKEN))
    missing_status, _, missing_body = call("GET", f"/v1/cases/{uuid.uuid4()}/evidence-export", _auth(FOREIGN_TOKEN))
    assert foreign_status == missing_status == 404
    assert json.loads(foreign_body) == json.loads(missing_body)
    assert str(evidence_api["case_id"]) not in json.loads(foreign_body)["detail"]
    assert _audit_count(evidence_api["tenant_id"], "evidence.export") == 0
    assert _audit_count(evidence_api["foreign_tenant_id"], "evidence.export") == 0
