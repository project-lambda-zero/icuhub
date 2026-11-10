"""Evidence manifest: each of the five evidence kinds exports, verifies offline, and rejects a mismatched digest."""

from __future__ import annotations

import asyncio
import base64
import copy
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core.auth_types import Caller
from icuhub.core.correlation import link_finding, record_raw_evidence
from icuhub.core.evidence_export import (
    _action,
    _approval,
    _canonical,
    _digest,
    _outcome_digest,
    export_evidence_bundle,
    verify_evidence_bundle,
)
from icuhub.kit.testing import RouteTransport
from icuhub.storage.db import session_scope
from icuhub.storage.models import (
    ActionPlanRow,
    ActionRequest,
    Approval,
    EvidenceItem,
    FileImport,
    Finding,
    RawBatch,
    Tenant,
)
from tests.core.helpers import make_services, new_connection

pytestmark = pytest.mark.usefixtures("clean_database")

_TS = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
_KINDS = ("raw_batch", "file_import", "action_plan", "approval", "outcome")


def _doc(uid: str) -> dict[str, Any]:
    purl = "pkg:pypi/requests@2.31.0"
    return {
        "class_uid": 2002,
        "finding_info": {"uid": uid, "title": f"title {uid}"},
        "vulnerabilities": [{"cve": {"uid": "CVE-2026-0001"}, "affected_packages": [{"name": "requests", "purl": purl}]}],
        "resources": [{"uid": purl}],
    }


def _finding(tenant_id: uuid.UUID, connection_id: uuid.UUID, uid: str) -> Finding:
    return Finding(
        tenant_id=tenant_id,
        connection_id=connection_id,
        stream="findings",
        source_uid=uid,
        fingerprint=f"fp_{uid.replace('-', '')}",
        ocsf_class_uid=2002,
        severity_id=3,
        title=f"title {uid}",
        ocsf_json=_doc(uid),
        revision_digest=f"sha256:{'0' * 64}",
        mapper_version=1,
    )


def _raw(tenant_id: uuid.UUID, connection_id: uuid.UUID) -> RawBatch:
    return RawBatch(
        tenant_id=tenant_id,
        connection_id=connection_id,
        origin="stream",
        stream="findings",
        digest=f"sha256:{'a' * 64}",
        record_count=1,
        parser_version="1",
        kek_id="local",
        dek_wrapped=b"wrapped",
        nonce=b"nonce-value",
        payload_enc=b"encrypted-payload",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )


def _action_request(
    tenant_id: uuid.UUID,
    connection_id: uuid.UUID,
    case_id: uuid.UUID,
    *,
    key: str,
    state: str,
    result_json: dict[str, Any] | None = None,
) -> ActionRequest:
    return ActionRequest(
        tenant_id=tenant_id,
        connection_id=connection_id,
        action="update_issue",
        classification="write",
        args_json={"issue": "ISSUE-7"},
        args_digest=f"sha256:{'b' * 64}",
        caller_id="auditor-kinds",
        correlation_id=str(case_id),
        idempotency_key=key,
        mode="live",
        state=state,
        result_json=result_json,
    )


def _auditor(tenant_id: uuid.UUID) -> Caller:
    return Caller(id="auditor-kinds", tenant_id=tenant_id, roles=frozenset({"auditor"}))


async def _seed_all_kinds(session: AsyncSession, tenant_id: uuid.UUID, tmp_path: Path) -> uuid.UUID:
    """Create one case with a real row behind each of the five evidence kinds and return the case id."""
    session.add(Tenant(id=tenant_id, slug=f"kinds-{tenant_id.hex[:8]}", display_name="Kinds"))
    await session.flush()
    services = make_services(RouteTransport({}), tmp_path / "kek")
    connection = await new_connection(session, services, tenant_id)

    raw = _raw(tenant_id, connection.id)
    session.add(raw)
    finding = _finding(tenant_id, connection.id, "obs-kinds")
    session.add(finding)
    await session.flush()
    case = await link_finding(session, finding)
    await record_raw_evidence(session, case, raw)

    file_import = FileImport(
        tenant_id=tenant_id,
        connection_id=connection.id,
        importer="csv",
        filename="scan.csv",
        digest=f"sha256:{'4' * 64}",
        size_bytes=128,
        state="done",
    )
    plan_action = _action_request(tenant_id, connection.id, case.id, key="plan-kinds", state="awaiting_approval")
    outcome_action = _action_request(
        tenant_id,
        connection.id,
        case.id,
        key="outcome-kinds",
        state="succeeded",
        result_json={"vendor_ref": "ISSUE-7", "status": "ok"},
    )
    session.add_all([file_import, plan_action, outcome_action])
    await session.flush()

    session.add(
        ActionPlanRow(
            action_request_id=plan_action.id,
            tenant_id=tenant_id,
            target_ref="issue/ISSUE-7",
            diff_json={"set": {"priority": 1}},
            preconditions_json={"status": "open"},
            request_json={"op": "update"},
            idempotency_key="plan-kinds",
            plan_hash=f"sha256:{'5' * 64}",
            changed=True,
        )
    )
    approval = Approval(
        tenant_id=tenant_id,
        action_request_id=plan_action.id,
        approver_group="ops",
        plan_hash=f"sha256:{'5' * 64}",
        expires_at=_TS + timedelta(days=1),
        decision="approved",
        decided_by="approver-kinds",
        decided_at=_TS,
        reason="reviewed",
    )
    session.add(approval)
    await session.flush()
    # Server-default timestamps are needed to compute the exporter's digests; refresh loads them.
    await session.refresh(plan_action)
    await session.refresh(outcome_action)
    await session.refresh(approval)

    session.add_all(
        [
            EvidenceItem(
                tenant_id=tenant_id,
                case_id=case.id,
                kind="file_import",
                digest=file_import.digest,
                ref_table="file_import",
                ref_id=file_import.id,
            ),
            EvidenceItem(
                tenant_id=tenant_id,
                case_id=case.id,
                kind="action_plan",
                digest=f"sha256:{'5' * 64}",
                ref_table="action_plan",
                ref_id=plan_action.id,
            ),
            EvidenceItem(
                tenant_id=tenant_id,
                case_id=case.id,
                kind="approval",
                digest=_digest(_approval(approval)),
                ref_table="approval",
                ref_id=approval.id,
            ),
            EvidenceItem(
                tenant_id=tenant_id,
                case_id=case.id,
                kind="outcome",
                digest=_outcome_digest(_action(outcome_action)),
                ref_table="action_request",
                ref_id=outcome_action.id,
            ),
        ]
    )
    await session.flush()
    return case.id


def _export_all_kinds(tmp_path: Path, signing_key: Ed25519PrivateKey) -> dict[str, Any]:
    async def scenario() -> dict[str, Any]:
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            case_id = await _seed_all_kinds(session, tenant_id, tmp_path)
            return await export_evidence_bundle(
                session,
                _auditor(tenant_id),
                case_id,
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )

    return asyncio.run(scenario())


def _resign(bundle: dict[str, Any], signing_key: Ed25519PrivateKey) -> None:
    payload_bytes = _canonical(bundle["payload"])
    bundle["payload_digest"] = _digest(bundle["payload"])
    bundle["signature"]["signature"] = base64.b64encode(signing_key.sign(payload_bytes)).decode("ascii")


def test_all_five_evidence_kinds_export_and_verify_offline(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()
    bundle = _export_all_kinds(tmp_path, signing_key)

    evidence = bundle["payload"]["evidence"]
    assert sorted(row["kind"] for row in evidence) == sorted(_KINDS)
    for row in evidence:
        assert row["ref_table"] == {
            "raw_batch": "raw_batch",
            "file_import": "file_import",
            "action_plan": "action_plan",
            "approval": "approval",
            "outcome": "action_request",
        }[row["kind"]]

    report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
    assert report["ok"] is True, report["failures"]
    assert report["evidence_references"]["checked"] == len(_KINDS)


@pytest.mark.parametrize("kind", _KINDS)
def test_mismatched_digest_fails_offline_for_each_kind(tmp_path: Path, kind: str) -> None:
    signing_key = Ed25519PrivateKey.generate()
    bundle = _export_all_kinds(tmp_path, signing_key)

    tampered = copy.deepcopy(bundle)
    target = next(row for row in tampered["payload"]["evidence"] if row["kind"] == kind)
    target["digest"] = f"sha256:{'9' * 64}"
    _resign(tampered, signing_key)

    report = verify_evidence_bundle(tampered, verification_key=signing_key.public_key())
    assert report["ok"] is False
    assert "evidence_reference_invalid" in report["failures"]
    assert report["evidence_references"]["failures"] == [f"{target['id']}:{kind}:{target['ref_id']}"]
