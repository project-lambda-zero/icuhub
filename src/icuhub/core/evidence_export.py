"""Signed, offline-verifiable evidence bundles for correlation cases (F7)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from icuhub.core import audit as audit_chain
from icuhub.core.auth_types import Caller
from icuhub.settings import get_settings
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
    Tenant,
    TicketLink,
)

__all__ = [
    "EvidenceExportError",
    "export_evidence_bundle",
    "load_signing_key",
    "load_verification_key",
    "main",
    "verify_evidence_bundle",
]

_FORMAT = "icuhub.evidence.v1"
_MAX_AUDIT_RECORDS = 10000
_MAX_INLINE_OUTCOME_BYTES = 4096
_SENSITIVE_PARTS = ("secret", "password", "token", "authorization", "credential", "private_key", "api_key")


class EvidenceExportError(RuntimeError):
    """The requested case cannot be exported without weakening evidence guarantees."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.utcoffset() is None:
        raise EvidenceExportError("naive database timestamp cannot be exported")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _uuid(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


def _public_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_signing_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceExportError("evidence signing key must be an Ed25519 private key")
    return key


def load_verification_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise EvidenceExportError("evidence verification key must be an Ed25519 public key")
    return key


def _keys(
    signing_key: Ed25519PrivateKey | None,
    verification_key: Ed25519PublicKey | None,
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    settings = get_settings()
    if signing_key is None:
        if settings.evidence_signing_key_file is None:
            raise EvidenceExportError("ICUHUB_EVIDENCE_SIGNING_KEY_FILE is not configured")
        signing_key = load_signing_key(settings.evidence_signing_key_file)
    if verification_key is None:
        if settings.evidence_verification_key_file is None:
            raise EvidenceExportError("ICUHUB_EVIDENCE_VERIFICATION_KEY_FILE is not configured")
        verification_key = load_verification_key(settings.evidence_verification_key_file)
    if signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) != verification_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw):
        raise EvidenceExportError("evidence signing and verification keys do not match")
    return signing_key, verification_key


async def _rows(session: AsyncSession, statement: Any) -> list[Any]:
    return list((await session.execute(statement)).scalars().all())


def _case(row: CorrelationCase) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "correlation_key": row.correlation_key,
        "key_version": row.key_version,
        "title": row.title,
        "severity_id": row.severity_id,
        "detection_state": row.detection_state,
        "remediation_state": row.remediation_state,
        "exception_state": row.exception_state,
        "exception_revision": row.exception_revision,
        "exception_scope_uids": list(row.exception_scope_uids or []),
        "exception_expires_at": _iso(row.exception_expires_at),
        "merged_into": _uuid(row.merged_into),
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


def _member(row: CaseMember) -> dict[str, Any]:
    return {
        "finding_id": _uuid(row.finding_id),
        "case_id": _uuid(row.case_id),
        "reason": row.reason,
        "linked_by": row.linked_by,
        "linked_at": _iso(row.linked_at),
    }


def _finding(row: Finding) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "connection_id": _uuid(row.connection_id),
        "target_id": _uuid(row.target_id),
        "stream": row.stream,
        "source_uid": row.source_uid,
        "fingerprint": row.fingerprint,
        "ocsf_class_uid": row.ocsf_class_uid,
        "severity_id": row.severity_id,
        "status": row.status,
        "title": row.title,
        "ocsf_digest": _digest(row.ocsf_json),
        "revision_digest": row.revision_digest,
        "raw_batch_id": _uuid(row.raw_batch_id),
        "mapper_version": row.mapper_version,
        "correlation_key": row.correlation_key,
        "first_seen": _iso(row.first_seen),
        "last_seen": _iso(row.last_seen),
        "resolved_at": _iso(row.resolved_at),
    }


def _connection(row: Connection) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "kind": row.kind,
        "slug": row.slug,
        "display_name": row.display_name,
        "config_digest": _digest(row.config_json),
        "egress_class": row.egress_class,
        "allowed_operations": row.allowed_operations,
        "status": row.status,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


def _raw_batch(row: RawBatch) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "connection_id": _uuid(row.connection_id),
        "sync_run_id": _uuid(row.sync_run_id),
        "origin": row.origin,
        "stream": row.stream,
        "digest": row.digest,
        "record_count": row.record_count,
        "parser_version": row.parser_version,
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
    }


def _file_import(row: FileImport) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "connection_id": _uuid(row.connection_id),
        "importer": row.importer,
        "filename": row.filename,
        "digest": row.digest,
        "size_bytes": row.size_bytes,
        "state": row.state,
        "raw_batch_id": _uuid(row.raw_batch_id),
        "counts": row.counts_json,
        "created_at": _iso(row.created_at),
    }


def _outcome_result(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {"content": None, "truncated": False, "sha256": None, "size_bytes": 0}
    encoded = _canonical(value)
    sensitive = any(part in key.lower() for key in value for part in _SENSITIVE_PARTS)
    return {
        "content": None,
        "truncated": len(encoded) > _MAX_INLINE_OUTCOME_BYTES or sensitive,
        "sha256": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        "size_bytes": len(encoded),
    }


def _action(row: ActionRequest) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "connection_id": _uuid(row.connection_id),
        "action": row.action,
        "classification": row.classification,
        "args_digest": row.args_digest,
        "caller_id": row.caller_id,
        "correlation_id": row.correlation_id,
        "idempotency_key": row.idempotency_key,
        "mode": row.mode,
        "outcome": {
            "state": row.state,
            "error_class": row.error_class,
            "result": _outcome_result(row.result_json),
        },
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


def _plan(row: ActionPlanRow) -> dict[str, Any]:
    return {
        "action_request_id": _uuid(row.action_request_id),
        "target_ref": row.target_ref,
        "plan_hash": row.plan_hash,
        "changed": row.changed,
        "idempotency_key": row.idempotency_key,
        "diff_digest": _digest(row.diff_json),
        "preconditions_digest": _digest(row.preconditions_json),
        "request_digest": _digest(row.request_json),
        "created_at": _iso(row.created_at),
    }


def _approval(row: Approval) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "action_request_id": _uuid(row.action_request_id),
        "approver_group": row.approver_group,
        "plan_hash": row.plan_hash,
        "expires_at": _iso(row.expires_at),
        "decision": row.decision,
        "decided_by": row.decided_by,
        "decided_at": _iso(row.decided_at),
        "reason": row.reason,
        "change_ref": row.change_ref,
        "created_at": _iso(row.created_at),
    }


def _ticket(row: TicketLink) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "route_id": _uuid(row.route_id),
        "case_id": _uuid(row.case_id),
        "connection_id": _uuid(row.connection_id),
        "state": row.state,
        "remote_key": row.remote_key,
        "remote_id": row.remote_id,
        "remote_url": row.remote_url,
        "remote_status": row.remote_status,
        "status_category": row.status_category,
        "last_outbound_revision": row.last_outbound_revision,
        "last_inbound_revision": row.last_inbound_revision,
        "last_synced_at": _iso(row.last_synced_at),
        "action_request_id": _uuid(row.action_request_id),
        "created_at": _iso(row.created_at),
    }


def _evidence(row: EvidenceItem) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "case_id": _uuid(row.case_id),
        "kind": row.kind,
        "digest": row.digest,
        "ref_table": row.ref_table,
        "ref_id": _uuid(row.ref_id),
        "created_at": _iso(row.created_at),
    }


def _audit(row: AuditRecord) -> dict[str, Any]:
    return {
        "id": _uuid(row.id),
        "tenant_id": _uuid(row.tenant_id),
        "seq": row.seq,
        "prev_hash": row.prev_hash,
        "hash": row.hash,
        "ts": _iso(row.ts),
        "caller_id": row.caller_id,
        "connection_id": _uuid(row.connection_id),
        "operation": row.operation,
        "classification": row.classification,
        "decision": row.decision,
        "approval_id": _uuid(row.approval_id),
        "args_digest": row.args_digest,
        "status": row.status,
        "correlation_id": row.correlation_id,
        "detail_json": row.detail_json,
    }


def _audit_object(row: dict[str, Any]) -> AuditRecord:
    return AuditRecord(
        id=uuid.UUID(row["id"]),
        tenant_id=uuid.UUID(row["tenant_id"]),
        seq=int(row["seq"]),
        prev_hash=row["prev_hash"],
        hash=row["hash"],
        ts=datetime.fromisoformat(str(row["ts"]).replace("Z", "+00:00")),
        caller_id=row["caller_id"],
        connection_id=uuid.UUID(row["connection_id"]) if row.get("connection_id") else None,
        operation=row["operation"],
        classification=row.get("classification"),
        decision=row.get("decision"),
        approval_id=uuid.UUID(row["approval_id"]) if row.get("approval_id") else None,
        args_digest=row.get("args_digest"),
        status=row["status"],
        correlation_id=row.get("correlation_id"),
        detail_json=row.get("detail_json") or {},
    )


def _verify_audit_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    failures: list[str] = []
    previous = audit_chain.GENESIS_PREV_HASH
    for expected_seq, row in enumerate(records, start=1):
        try:
            record = _audit_object(row)
            if record.seq != expected_seq:
                failures.append(f"seq:{record.seq}:sequence")
            if record.prev_hash != previous:
                failures.append(f"seq:{record.seq}:previous_hash")
            expected_hash = audit_chain._record_hash(record, previous)
            if record.hash != expected_hash:
                failures.append(f"seq:{record.seq}:hash")
            previous = record.hash
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(f"record:{expected_seq}:{type(exc).__name__}")
    return {"ok": not failures, "checked": len(records), "failures": failures}


def _verify_evidence_references(payload: dict[str, Any]) -> dict[str, Any]:
    raw = {row["id"]: row["digest"] for row in payload.get("raw_batches", [])}
    imports = {row["id"]: row["digest"] for row in payload.get("file_imports", [])}
    plans = {row["action_request_id"]: row["plan_hash"] for row in payload.get("plans", [])}
    failures: list[str] = []
    for item in payload.get("evidence", []):
        table = item.get("ref_table")
        ref_id = item.get("ref_id")
        expected = None
        if table == "raw_batch":
            expected = raw.get(ref_id)
        elif table == "file_import":
            expected = imports.get(ref_id)
        elif table == "action_plan":
            expected = plans.get(ref_id)
        if expected is None or expected != item.get("digest"):
            failures.append(f"{item.get('id')}:{table}:{ref_id}")
    return {"ok": not failures, "checked": len(payload.get("evidence", [])), "failures": failures}


async def export_evidence_bundle(
    session: AsyncSession,
    caller: Caller,
    case_id: uuid.UUID,
    *,
    signing_key: Ed25519PrivateKey | None = None,
    verification_key: Ed25519PublicKey | None = None,
) -> dict[str, Any]:
    """Export one tenant-scoped case and append the audited export read."""
    signing_key, verification_key = _keys(signing_key, verification_key)
    case = (
        await session.execute(
            select(CorrelationCase).where(
                CorrelationCase.id == case_id,
                CorrelationCase.tenant_id == caller.tenant_id,
            )
        )
    ).scalar_one_or_none()
    tenant = await session.get(Tenant, caller.tenant_id)
    if case is None or tenant is None:
        raise EvidenceExportError("case evidence is unavailable")

    members = await _rows(session, select(CaseMember).where(CaseMember.case_id == case_id).order_by(CaseMember.finding_id))
    finding_ids = [row.finding_id for row in members]
    findings = await _rows(session, select(Finding).where(Finding.id.in_(finding_ids)).order_by(Finding.id)) if finding_ids else []
    tickets = await _rows(session, select(TicketLink).where(TicketLink.case_id == case_id).order_by(TicketLink.id))
    actions = await _rows(
        session,
        select(ActionRequest).where(ActionRequest.correlation_id == str(case_id)).order_by(ActionRequest.id),
    )
    action_ids = [row.id for row in actions]
    plans = await _rows(session, select(ActionPlanRow).where(ActionPlanRow.action_request_id.in_(action_ids)).order_by(ActionPlanRow.action_request_id)) if action_ids else []
    approvals = await _rows(session, select(Approval).where(Approval.action_request_id.in_(action_ids)).order_by(Approval.id)) if action_ids else []
    evidence = await _rows(session, select(EvidenceItem).where(EvidenceItem.case_id == case_id).order_by(EvidenceItem.id))

    raw_ids = {row.raw_batch_id for row in findings if row.raw_batch_id is not None}
    raw_ids.update(row.ref_id for row in evidence if row.ref_table == "raw_batch")
    import_ids = {row.ref_id for row in evidence if row.ref_table == "file_import"}
    raw_batches = await _rows(session, select(RawBatch).where(RawBatch.id.in_(raw_ids)).order_by(RawBatch.id)) if raw_ids else []
    file_imports = await _rows(session, select(FileImport).where(FileImport.id.in_(import_ids)).order_by(FileImport.id)) if import_ids else []

    connection_ids = {row.connection_id for row in findings + raw_batches + file_imports + actions + tickets}
    connections = await _rows(session, select(Connection).where(Connection.id.in_(connection_ids)).order_by(Connection.id)) if connection_ids else []
    rule_ids = {row.rule_id for row in actions if row.rule_id is not None}
    rules = await _rows(session, select(PolicyRule).where(PolicyRule.id.in_(rule_ids)).order_by(PolicyRule.id)) if rule_ids else []
    rule_by_id = {row.id: row for row in rules}

    await audit_chain.append(
        session,
        caller.tenant_id,
        ts=datetime.now(UTC),
        caller_id=caller.id,
        operation="evidence.export",
        classification="read",
        status="succeeded",
        correlation_id=str(case_id),
        detail_json={"case_id": str(case_id), "evidence_items": len(evidence)},
    )
    audit_records = await _rows(session, select(AuditRecord).order_by(AuditRecord.seq).limit(_MAX_AUDIT_RECORDS + 1))
    if len(audit_records) > _MAX_AUDIT_RECORDS:
        raise EvidenceExportError("audit chain exceeds the evidence export record bound")
    chain_result = await audit_chain.verify_chain(session, caller.tenant_id)
    if not chain_result.ok:
        raise EvidenceExportError("tenant audit chain is invalid")

    payload = {
        "schema_version": 1,
        "exported_at": _iso(datetime.now(UTC)),
        "caller": {
            "id": caller.id,
            "kind": caller.kind,
            "roles": sorted(caller.roles),
            "groups": sorted(caller.groups),
        },
        "tenant": {"id": _uuid(tenant.id), "slug": tenant.slug, "display_name": tenant.display_name},
        "correlation_case": _case(case),
        "case_members": [_member(row) for row in members],
        "findings": [_finding(row) for row in findings],
        "connections": [_connection(row) for row in connections],
        "ticket_links": [_ticket(row) for row in tickets],
        "vendor_references": [
            {
                "kind": "ticket_link",
                "value": row.remote_key or row.remote_id,
                "remote_id": row.remote_id,
                "url": row.remote_url,
                "connection_id": _uuid(row.connection_id),
                "case_id": _uuid(row.case_id),
            }
            for row in tickets
            if row.remote_key or row.remote_id
        ]
        + [
            {"kind": "action_outcome", "value": row.result_json.get("vendor_ref"), "action_request_id": _uuid(row.id)}
            for row in actions
            if row.result_json and row.result_json.get("vendor_ref")
        ],
        "actions": [_action(row) for row in actions],
        "plans": [_plan(row) for row in plans],
        "approvals": [_approval(row) for row in approvals],
        "policy_decisions": [
            {
                "action_request_id": _uuid(row.id),
                "rule_id": _uuid(row.rule_id),
                "decision": row.decision,
                "rule_name": rule_by_id[row.rule_id].name if row.rule_id in rule_by_id else None,
                "rule_priority": rule_by_id[row.rule_id].priority if row.rule_id in rule_by_id else None,
            }
            for row in actions
        ],
        "evidence": [_evidence(row) for row in evidence],
        "raw_batches": [_raw_batch(row) for row in raw_batches],
        "file_imports": [_file_import(row) for row in file_imports],
        "audit": {
            "records": [_audit(row) for row in audit_records],
            "chain": {"ok": chain_result.ok, "checked": chain_result.checked, "failures": []},
        },
    }
    payload_bytes = _canonical(payload)
    signature = signing_key.sign(payload_bytes)
    return {
        "format": _FORMAT,
        "payload_digest": "sha256:" + hashlib.sha256(payload_bytes).hexdigest(),
        "payload": payload,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": _key_id(verification_key),
            "public_key_pem": _public_pem(verification_key),
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_evidence_bundle(bundle: dict[str, Any], *, verification_key: Ed25519PublicKey) -> dict[str, Any]:
    """Verify digest, signature, embedded audit chain, and evidence references offline."""
    failures: list[str] = []
    audit_report: dict[str, Any] = {"ok": False, "checked": 0, "failures": []}
    evidence_report: dict[str, Any] = {"ok": False, "checked": 0, "failures": []}
    try:
        payload = bundle["payload"]
        payload_bytes = _canonical(payload)
        expected_digest = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
        if bundle.get("payload_digest") != expected_digest:
            failures.append("payload_digest_mismatch")
        signature = bundle["signature"]
        if signature.get("algorithm") != "Ed25519":
            failures.append("signature_algorithm_invalid")
        if signature.get("key_id") != _key_id(verification_key) or signature.get("public_key_pem") != _public_pem(verification_key):
            failures.append("verification_key_mismatch")
        try:
            verification_key.verify(base64.b64decode(signature["signature"], validate=True), payload_bytes)
        except (InvalidSignature, KeyError, ValueError):
            failures.append("signature_invalid")
        audit_report = _verify_audit_records(payload["audit"]["records"])
        if not audit_report["ok"]:
            failures.append("audit_chain_invalid")
        evidence_report = _verify_evidence_references(payload)
        if not evidence_report["ok"]:
            failures.append("evidence_reference_invalid")
    except (KeyError, TypeError, ValueError, EvidenceExportError) as exc:
        failures.append(f"bundle_structure_invalid:{type(exc).__name__}")
    return {
        "ok": not failures,
        "failures": failures,
        "audit_chain": audit_report,
        "evidence_references": evidence_report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="icuhub-evidence")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify a signed evidence bundle without database access")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "verify":
        try:
            bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
            if not isinstance(bundle, dict):
                raise ValueError("bundle must be a JSON object")
            report = verify_evidence_bundle(bundle, verification_key=load_verification_key(args.public_key))
        except (OSError, ValueError, EvidenceExportError) as exc:
            report = {"ok": False, "failures": [f"bundle_read_failed:{type(exc).__name__}"]}
        print(json.dumps(report, sort_keys=True))
        return 0 if report["ok"] else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
