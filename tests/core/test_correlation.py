"""Correlation key rules and case lifecycle (FR-COR-01..04)."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from icuhub.core.correlation import correlation_key, link_finding, merge_cases, split_finding
from icuhub.kit.testing import RouteTransport
from icuhub.storage.db import session_scope
from icuhub.storage.models import CaseMember, CorrelationCase, Finding, Tenant
from tests.core.helpers import caller_for, make_services, new_connection

CVE_DOC: dict[str, Any] = {
    "class_uid": 2002,
    "finding_info": {"uid": "obs-1", "title": "requests vulnerability"},
    "vulnerabilities": [
        {"cve": {"uid": "CVE-2026-0001"}, "affected_packages": [{"name": "requests", "purl": "pkg:pypi/requests@2.31.0"}]}
    ],
    "resources": [{"uid": "pkg:pypi/requests@2.31.0"}],
}


def test_same_cve_same_asset_correlates_across_kinds() -> None:
    assert correlation_key(CVE_DOC, connector_kind="fortify_ssc") == correlation_key(CVE_DOC, connector_kind="mend_sca")


def test_different_asset_does_not_merge() -> None:
    other = {**CVE_DOC, "resources": [{"uid": "pkg:pypi/urllib3@2.0.0"}]}
    assert correlation_key(CVE_DOC, connector_kind="x") != correlation_key(other, connector_kind="x")


def test_sca_version_is_stripped_from_identity() -> None:
    older = {
        **CVE_DOC,
        "vulnerabilities": [
            {"cve": {"uid": "CVE-2026-0001"}, "affected_packages": [{"name": "requests", "purl": "pkg:pypi/requests@2.20.0"}]}
        ],
        "resources": [{"uid": "pkg:pypi/requests@2.20.0"}],
    }
    assert correlation_key(CVE_DOC, connector_kind="x") == correlation_key(older, connector_kind="x")


def test_sast_path_normalization() -> None:
    def doc(path: str) -> dict[str, Any]:
        return {
            "class_uid": 2002,
            "finding_info": {"uid": "x"},
            "vulnerabilities": [{"cwe": {"uid": "CWE-89"}, "affected_code": [{"file": {"path": path}, "start_line": 12}]}],
            "resources": [{"hostname": "build01"}],
        }

    assert correlation_key(doc("./src/app.py"), connector_kind="x") == correlation_key(
        doc("src\\app.py"), connector_kind="y"
    )


def test_weak_identity_gets_no_key() -> None:
    assert correlation_key({"class_uid": 2004, "finding_info": {"uid": "x"}}, connector_kind="x") is None
    no_cve = {"class_uid": 2002, "finding_info": {"uid": "x"}, "resources": [{"hostname": "h"}]}
    assert correlation_key(no_cve, connector_kind="x") is None


def test_compliance_uses_check_identity() -> None:
    doc = {
        "class_uid": 2003,
        "finding_info": {"uid": "x"},
        "compliance": {"control": "CIS 1.1", "checks": [{"uid": "cis-1.1"}]},
        "resources": [{"uid": "arn:aws:iam::123:role/admin"}],
    }
    key, version = correlation_key(doc, connector_kind="prisma_cloud")  # type: ignore[misc]
    assert version == 1
    assert "cis-1.1" in key


def _finding(tenant_id: uuid.UUID, connection_id: uuid.UUID, uid: str, severity: int = 3) -> Finding:
    doc = {**CVE_DOC, "finding_info": {"uid": uid, "title": f"title {uid}"}}
    return Finding(
        tenant_id=tenant_id,
        connection_id=connection_id,
        stream="findings",
        source_uid=uid,
        fingerprint=f"fp_{uid.replace('-', '')}",
        ocsf_class_uid=2002,
        severity_id=severity,
        title=f"title {uid}",
        ocsf_json=doc,
        revision_digest=f"sha256:{'0' * 64}",
        mapper_version=1,
    )


def test_link_merge_split(tmp_path: object, clean_database: None) -> None:
    async def scenario() -> None:
        make_services(RouteTransport({}), tmp_path / "kek")
        tenant_id = uuid.uuid4()
        async with session_scope(tenant_id) as session:
            session.add(Tenant(id=tenant_id, slug=f"t-{tenant_id.hex[:8]}", display_name="T"))
            await session.flush()
            services = make_services(RouteTransport({}), tmp_path / "kek")
            connection = await new_connection(session, services, tenant_id)
            first = _finding(tenant_id, connection.id, "obs-1", severity=3)
            second = _finding(tenant_id, connection.id, "obs-2", severity=5)
            session.add_all([first, second])
            await session.flush()
            case = await link_finding(session, first)
            same_case = await link_finding(session, second)
            assert same_case.id == case.id
            assert case.severity_id == 5
            members = (await session.execute(__import__("sqlalchemy").select(CaseMember))).scalars().all()
            assert len(members) == 2
            caller = caller_for(tenant_id)
            other = CorrelationCase(
                tenant_id=tenant_id, correlation_key="v1|own|other", key_version=1, title="other", severity_id=1
            )
            session.add(other)
            await session.flush()
            merged = await merge_cases(session, caller, other.id, case.id)
            assert merged.id == case.id
            split_case = await split_finding(session, caller, second.id)
            assert split_case.id != case.id
            assert split_case.remediation_state == case.remediation_state

    asyncio.run(scenario())
