"""Evidence lineage: superseded raw batches, merge and split reach, offline audit verification."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from icuhub.core.audit import VerifyResult, verify_chain
from icuhub.core.audit import append as audit_append
from icuhub.core.auth_types import Caller
from icuhub.core.correlation import link_finding, merge_cases, record_raw_evidence, split_finding
from icuhub.core.evidence_export import export_evidence_bundle, verify_evidence_bundle
from icuhub.kit.testing import RouteTransport
from icuhub.storage.db import create_engine, session_scope
from icuhub.storage.models import (
    ActionRequest,
    CorrelationCase,
    EvidenceItem,
    Finding,
    RawBatch,
    Tenant,
    TicketLink,
    TicketRoute,
)
from tests.core.helpers import caller_for, make_services, new_connection

pytestmark = pytest.mark.usefixtures("clean_database")

_TS = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def _doc(uid: str, cve: str, package: str) -> dict[str, Any]:
    purl = f"pkg:pypi/{package}@2.31.0"
    return {
        "class_uid": 2002,
        "finding_info": {"uid": uid, "title": f"title {uid}"},
        "vulnerabilities": [{"cve": {"uid": cve}, "affected_packages": [{"name": package, "purl": purl}]}],
        "resources": [{"uid": purl}],
    }


def _finding(
    tenant_id: uuid.UUID,
    connection_id: uuid.UUID,
    uid: str,
    *,
    cve: str = "CVE-2026-0001",
    package: str = "requests",
    raw_batch_id: uuid.UUID | None = None,
) -> Finding:
    return Finding(
        tenant_id=tenant_id,
        connection_id=connection_id,
        stream="findings",
        source_uid=uid,
        fingerprint=f"fp_{uid.replace('-', '')}",
        ocsf_class_uid=2002,
        severity_id=3,
        title=f"title {uid}",
        ocsf_json=_doc(uid, cve, package),
        revision_digest=f"sha256:{'0' * 64}",
        mapper_version=1,
        raw_batch_id=raw_batch_id,
    )


def _raw(tenant_id: uuid.UUID, connection_id: uuid.UUID, digest_char: str) -> RawBatch:
    return RawBatch(
        tenant_id=tenant_id,
        connection_id=connection_id,
        origin="stream",
        stream="findings",
        digest=f"sha256:{digest_char * 64}",
        record_count=1,
        parser_version="1",
        kek_id="local",
        dek_wrapped=b"wrapped",
        nonce=b"nonce-value",
        payload_enc=b"encrypted-payload",
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )


def _auditor(tenant_id: uuid.UUID) -> Caller:
    return Caller(id="auditor-lineage", tenant_id=tenant_id, roles=frozenset({"auditor"}))


async def _seed_tenant(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    session.add(Tenant(id=tenant_id, slug=f"lineage-{tenant_id.hex[:8]}", display_name="Lineage"))
    await session.flush()


async def _purge_seq_two(owner: AsyncEngine, tenant_id: uuid.UUID) -> None:
    """Purge one audit row the way the retention path does: owner role, append-only trigger off for this transaction."""
    async with AsyncSession(owner) as session, session.begin():
        await session.execute(text("ALTER TABLE audit_record DISABLE TRIGGER audit_append_only"))
        await session.execute(
            text(
                "UPDATE audit_record SET detail_json = CAST('{}' AS jsonb) "
                "WHERE tenant_id = :tenant_id AND seq = 2"
            ),
            {"tenant_id": tenant_id},
        )
        await session.execute(text("ALTER TABLE audit_record ENABLE TRIGGER audit_append_only"))


def test_superseded_raw_batch_remains_in_case_export(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()

    async def scenario() -> tuple[dict[str, Any], str, str]:
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            await _seed_tenant(session, tenant_id)
            services = make_services(RouteTransport({}), tmp_path / "kek")
            connection = await new_connection(session, services, tenant_id)
            first = _raw(tenant_id, connection.id, "a")
            second = _raw(tenant_id, connection.id, "b")
            session.add_all([first, second])
            await session.flush()
            row = _finding(tenant_id, connection.id, "obs-superseded", raw_batch_id=first.id)
            session.add(row)
            await session.flush()
            case = await link_finding(session, row)
            await record_raw_evidence(session, case, first)
            # A later observation replaces the finding's current batch; the earlier batch must stay evidence.
            row.raw_batch_id = second.id
            await record_raw_evidence(session, case, second)
            await session.flush()
            bundle = await export_evidence_bundle(
                session,
                _auditor(tenant_id),
                case.id,
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )
            return bundle, str(first.id), str(second.id)

    bundle, first_id, second_id = asyncio.run(scenario())
    payload = bundle["payload"]
    assert {row["ref_id"] for row in payload["evidence"]} == {first_id, second_id}
    assert {row["id"] for row in payload["raw_batches"]} == {first_id, second_id}
    report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
    assert report["ok"] is True, report["failures"]


def test_record_raw_evidence_keeps_one_row_per_case_and_batch(tmp_path: Path) -> None:
    async def scenario() -> int:
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            await _seed_tenant(session, tenant_id)
            services = make_services(RouteTransport({}), tmp_path / "kek")
            connection = await new_connection(session, services, tenant_id)
            raw = _raw(tenant_id, connection.id, "c")
            session.add(raw)
            await session.flush()
            row = _finding(tenant_id, connection.id, "obs-repeat", raw_batch_id=raw.id)
            session.add(row)
            await session.flush()
            case = await link_finding(session, row)
            await record_raw_evidence(session, case, raw)
            await record_raw_evidence(session, case, raw)
            await session.flush()
            rows = (
                await session.execute(
                    select(EvidenceItem).where(EvidenceItem.case_id == case.id, EvidenceItem.ref_id == raw.id)
                )
            ).scalars().all()
            return len(rows)

    assert asyncio.run(scenario()) == 1


def test_offline_verifier_accepts_purged_audit_row(owner_database_url: str, app_database_url: str) -> None:
    signing_key = Ed25519PrivateKey.generate()
    case_id = uuid.uuid4()

    async def scenario() -> tuple[VerifyResult, dict[str, Any]]:
        owner = create_engine(owner_database_url)
        app = create_engine(app_database_url)
        try:
            tenant_id = uuid.uuid4()
            async with AsyncSession(owner) as session, session.begin():
                session.add(Tenant(id=tenant_id, slug=f"purge-{tenant_id.hex[:8]}", display_name="Purge"))
                await session.flush()
                session.add(
                    CorrelationCase(
                        id=case_id,
                        tenant_id=tenant_id,
                        correlation_key="v1|cve|CVE-2026-0001|host:asset-1",
                        key_version=1,
                        title="Purged chain",
                        severity_id=3,
                    )
                )
            for index in range(3):
                async with session_scope(tenant_id, engine=app) as session:
                    await audit_append(
                        session,
                        tenant_id,
                        ts=_TS + timedelta(seconds=index),
                        caller_id="svc-scanner",
                        operation=f"vendor.op_{index}",
                        status="succeeded",
                        detail_json={"index": index},
                    )
            await _purge_seq_two(owner, tenant_id)
            async with session_scope(tenant_id, engine=app) as session:
                db_result = await verify_chain(session, tenant_id)
                bundle = await export_evidence_bundle(
                    session,
                    _auditor(tenant_id),
                    case_id,
                    signing_key=signing_key,
                    verification_key=signing_key.public_key(),
                )
            return db_result, bundle
        finally:
            await owner.dispose()
            await app.dispose()

    db_result, bundle = asyncio.run(scenario())
    assert db_result.ok is True, db_result.failures
    assert db_result.checked == 3
    records = bundle["payload"]["audit"]["records"]
    assert any(record["detail_json"] == {} for record in records)
    report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
    assert report["audit_chain"]["ok"] is True, report["audit_chain"]["failures"]
    assert report["audit_chain"]["checked"] >= 3


def test_merged_source_evidence_tickets_and_actions_reach_target_export(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()

    async def scenario() -> tuple[dict[str, Any], str, str, str, str]:
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            await _seed_tenant(session, tenant_id)
            services = make_services(RouteTransport({}), tmp_path / "kek")
            connection = await new_connection(session, services, tenant_id)
            raw = _raw(tenant_id, connection.id, "d")
            session.add(raw)
            await session.flush()
            source_row = _finding(tenant_id, connection.id, "obs-source", raw_batch_id=raw.id)
            target_row = _finding(tenant_id, connection.id, "obs-target", cve="CVE-2026-0002", package="urllib3")
            session.add_all([source_row, target_row])
            await session.flush()
            source = await link_finding(session, source_row)
            target = await link_finding(session, target_row)
            assert source.id != target.id
            await record_raw_evidence(session, source, raw)
            route = TicketRoute(
                tenant_id=tenant_id,
                name="lineage-route",
                connection_id=connection.id,
                action="create_issue",
                match_json={},
                template_json={},
            )
            session.add(route)
            await session.flush()
            ticket = TicketLink(
                tenant_id=tenant_id,
                route_id=route.id,
                case_id=source.id,
                connection_id=connection.id,
                state="open",
                remote_key="SEC-1",
                remote_id="10001",
                remote_url="https://tracker.invalid/SEC-1",
            )
            session.add(ticket)
            action = ActionRequest(
                tenant_id=tenant_id,
                connection_id=connection.id,
                action="create_issue",
                classification="write",
                args_json={"summary": "lineage"},
                args_digest=f"sha256:{'e' * 64}",
                caller_id="operator-lineage",
                correlation_id=str(source.id),
                idempotency_key="lineage-merge-1",
                state="succeeded",
            )
            session.add(action)
            await session.flush()
            await merge_cases(session, caller_for(tenant_id), source.id, target.id)
            await session.flush()
            bundle = await export_evidence_bundle(
                session,
                _auditor(tenant_id),
                target.id,
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )
            return bundle, str(raw.id), str(ticket.id), str(action.id), str(target.id)

    bundle, raw_id, ticket_id, action_id, target_id = asyncio.run(scenario())
    payload = bundle["payload"]
    assert {row["ref_id"] for row in payload["evidence"]} == {raw_id}
    assert [row["id"] for row in payload["ticket_links"]] == [ticket_id]
    assert [row["id"] for row in payload["actions"]] == [action_id]
    assert len(payload["case_members"]) == 2
    assert all(row["case_id"] == target_id for row in payload["case_members"])
    report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
    assert report["ok"] is True, report["failures"]


def test_split_case_carries_the_finding_current_raw_batch(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()

    async def scenario() -> tuple[dict[str, Any], dict[str, Any], str, str]:
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            await _seed_tenant(session, tenant_id)
            services = make_services(RouteTransport({}), tmp_path / "kek")
            connection = await new_connection(session, services, tenant_id)
            raw = _raw(tenant_id, connection.id, "f")
            session.add(raw)
            await session.flush()
            row = _finding(tenant_id, connection.id, "obs-split", raw_batch_id=raw.id)
            session.add(row)
            await session.flush()
            origin = await link_finding(session, row)
            await record_raw_evidence(session, origin, raw)
            split_case = await split_finding(session, caller_for(tenant_id), row.id)
            await session.flush()
            split_bundle = await export_evidence_bundle(
                session,
                _auditor(tenant_id),
                split_case.id,
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )
            origin_bundle = await export_evidence_bundle(
                session,
                _auditor(tenant_id),
                origin.id,
                signing_key=signing_key,
                verification_key=signing_key.public_key(),
            )
            return split_bundle, origin_bundle, str(raw.id), str(split_case.id)

    split_bundle, origin_bundle, raw_id, split_id = asyncio.run(scenario())
    assert split_bundle["payload"]["correlation_case"]["id"] == split_id
    assert split_id != origin_bundle["payload"]["correlation_case"]["id"]
    split_payload = split_bundle["payload"]
    assert {row["ref_id"] for row in split_payload["evidence"]} == {raw_id}
    assert [row["id"] for row in split_payload["raw_batches"]] == [raw_id]
    assert {row["ref_id"] for row in origin_bundle["payload"]["evidence"]} == {raw_id}
    for bundle in (split_bundle, origin_bundle):
        report = verify_evidence_bundle(bundle, verification_key=signing_key.public_key())
        assert report["ok"] is True, report["failures"]
