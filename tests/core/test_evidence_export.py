"""Signed evidence export and standalone verification against real PostgreSQL."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from icuhub.core.audit import append as audit_append
from icuhub.core.audit import verify_chain
from icuhub.core.auth_types import Caller
from icuhub.core.evidence_export import export_evidence_bundle, main, verify_evidence_bundle
from icuhub.storage.db import session_scope
from icuhub.storage.models import AuditRecord, CorrelationCase, Tenant

pytestmark = pytest.mark.usefixtures("clean_database")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _resign(bundle: dict[str, Any], signing_key: Ed25519PrivateKey) -> None:
    payload = _canonical(bundle["payload"])
    bundle["payload_digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    bundle["signature"]["signature"] = base64.b64encode(signing_key.sign(payload)).decode("ascii")


@pytest.fixture
def evidence_keys(tmp_path: Path) -> dict[str, Any]:
    signing_key = Ed25519PrivateKey.generate()
    verification_key = signing_key.public_key()
    signing_path = tmp_path / "evidence-signing.pem"
    verification_path = tmp_path / "evidence-verification.pem"
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
    return {
        "signing_key": signing_key,
        "verification_key": verification_key,
        "signing_path": signing_path,
        "verification_path": verification_path,
    }


@pytest.fixture
def exported(evidence_keys: dict[str, Any]) -> dict[str, Any]:
    tenant_id = uuid.uuid4()
    case_id = uuid.uuid4()
    caller = Caller(id="auditor-core", tenant_id=tenant_id, roles=frozenset({"auditor"}))

    async def scenario() -> dict[str, Any]:
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex[:8]}", display_name="Tenant"))
            await session.flush()
            session.add(
                CorrelationCase(
                    id=case_id,
                    tenant_id=tenant_id,
                    correlation_key="v1|own|empty",
                    key_version=1,
                    title="Empty evidence case",
                    severity_id=1,
                )
            )
            await session.flush()
            await audit_append(
                session,
                tenant_id,
                ts=datetime.now(UTC),
                caller_id=caller.id,
                operation="case.review",
                classification="read",
                status="succeeded",
                correlation_id=str(case_id),
                detail_json={"case_id": str(case_id)},
            )
            return await export_evidence_bundle(
                session,
                caller,
                case_id,
                signing_key=evidence_keys["signing_key"],
                verification_key=evidence_keys["verification_key"],
            )

    bundle = asyncio.run(scenario())
    return {"bundle": bundle, "tenant_id": tenant_id, "case_id": case_id, **evidence_keys}


def test_empty_case_exports_with_audited_read_and_verifies_offline(exported: dict[str, Any]) -> None:
    bundle = exported["bundle"]
    payload = bundle["payload"]

    assert payload["correlation_case"]["title"] == "Empty evidence case"
    assert payload["case_members"] == []
    assert payload["findings"] == []
    assert payload["evidence"] == []
    assert payload["raw_batches"] == []
    assert payload["caller"]["id"] == "auditor-core"
    assert payload["tenant"]["id"] == str(exported["tenant_id"])
    assert payload["audit"]["records"][-1]["operation"] == "evidence.export"
    assert payload["audit"]["records"][-1]["classification"] == "read"
    assert payload["audit"]["records"][-1]["correlation_id"] == str(exported["case_id"])
    assert payload["audit"]["chain"]["ok"] is True

    report = verify_evidence_bundle(bundle, verification_key=exported["verification_key"])
    assert report["ok"] is True, report
    assert report["audit_chain"]["checked"] == 2
    assert report["evidence_references"]["checked"] == 0

    private_pem = exported["signing_key"].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    assert private_pem not in json.dumps(bundle)
    assert "private_key" not in bundle["signature"]

    async def database_chain() -> None:
        async with session_scope(exported["tenant_id"]) as session:
            result = await verify_chain(session, exported["tenant_id"])
            assert result.ok is True
            records = list((await session.scalars(select(AuditRecord).order_by(AuditRecord.seq))).all())
            assert [row.operation for row in records] == ["case.review", "evidence.export"]

    asyncio.run(database_chain())


def test_tampering_fails_digest_signature_and_audit_chain_checks(exported: dict[str, Any]) -> None:
    bundle = exported["bundle"]
    verification_key = exported["verification_key"]

    digest_tamper = deepcopy(bundle)
    digest_tamper["payload"]["correlation_case"]["title"] = "Changed"
    digest_report = verify_evidence_bundle(digest_tamper, verification_key=verification_key)
    assert digest_report["ok"] is False
    assert "payload_digest_mismatch" in digest_report["failures"]

    signature_tamper = deepcopy(digest_tamper)
    signature_tamper["payload_digest"] = _digest(signature_tamper["payload"])
    signature_report = verify_evidence_bundle(signature_tamper, verification_key=verification_key)
    assert signature_report["ok"] is False
    assert "signature_invalid" in signature_report["failures"]

    chain_tamper = deepcopy(bundle)
    chain_tamper["payload"]["audit"]["records"][0]["operation"] = "case.forged"
    _resign(chain_tamper, exported["signing_key"])
    chain_report = verify_evidence_bundle(chain_tamper, verification_key=verification_key)
    assert chain_report["ok"] is False
    assert "audit_chain_invalid" in chain_report["failures"]

    wrong_key = verify_evidence_bundle(bundle, verification_key=Ed25519PrivateKey.generate().public_key())
    assert wrong_key["ok"] is False
    assert "verification_key_mismatch" in wrong_key["failures"]


def test_standalone_cli_verifies_without_database(
    exported: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(exported["bundle"]), encoding="utf-8")

    assert main(["verify", str(bundle_path), "--public-key", str(exported["verification_path"])]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is True

    tampered = deepcopy(exported["bundle"])
    tampered["payload"]["tenant"]["display_name"] = "Changed"
    bundle_path.write_text(json.dumps(tampered), encoding="utf-8")
    assert main(["verify", str(bundle_path), "--public-key", str(exported["verification_path"])]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is False
